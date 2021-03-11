///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherManager.cpp: implementation of the CFilterCipherManager class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the IFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterCipherManager.h"
#include "CFilterControl.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE


NTSTATUS CFilterCipherManager::Init(ULONG bufferSize)
{
	// some compile time checks
	C_ASSERT(CFilterHeader::c_align >= CFilterHeader::c_check);
	C_ASSERT(0 == (CFilterHeader::c_align % CFilterBase::c_sectorSize));
	C_ASSERT(0 == (CFilterHeader::c_check % CFilterBase::c_sectorSize));

	PAGED_CODE();

	// align buffer
	bufferSize = (bufferSize + (CFilterHeader::c_align- 1)) & ~(CFilterHeader::c_align - 1);

	// adequate buffer size ?
	if(bufferSize > m_bufferSize)
	{
		Close();

		m_buffer = (UCHAR*) ExAllocatePool(NonPagedPool, bufferSize);

		if(!m_buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		m_bufferSize = bufferSize;

		m_readWrite.Mdl = IoAllocateMdl(m_buffer, m_bufferSize, false, false, 0);

		if(!m_readWrite.Mdl)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		MmBuildMdlForNonPagedPool(m_readWrite.Mdl);

		// set common used values
		m_readWrite.Buffer = m_buffer;
		m_readWrite.Flags  = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
		m_readWrite.Wait   = true;
	}

	ASSERT(m_buffer);
	ASSERT(m_bufferSize);
	ASSERT(m_readWrite.Mdl);
	ASSERT(m_readWrite.Buffer);

	// always clear buffer
	RtlZeroMemory(m_buffer, m_bufferSize);

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterCipherManager::Close()
{
	PAGED_CODE();

	if(m_buffer)
	{
		ExFreePool(m_buffer);
		m_buffer = 0;
	}

	m_bufferSize = 0;

	m_readWrite.Buffer = 0;

	if(m_readWrite.Mdl)
	{
		IoFreeMdl(m_readWrite.Mdl);	
		m_readWrite.Mdl = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::ReadHeader(FILE_OBJECT *file, ULONG flags)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_extension);

	if(!m_fileSize.QuadPart)
	{
		// get current EOF
		CFilterBase::GetFileSize(m_extension->Lower, file, &m_fileSize);
	}

	if(!m_fileSize.QuadPart)
	{
		// Return this special value for zero sized files
		return STATUS_MAPPED_FILE_SIZE_ZERO;
	}
	if(m_fileSize.QuadPart < CFilterHeader::c_align)
	{
		// File is too small to have Header
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = Init(CFilterHeader::c_align);

	if(NT_SUCCESS(status))
	{
		bool cached = false;

		if(flags & TRACK_USE_CACHE)
		{
			DBGPRINT(("ReadHeader -INFO: FO[0x%p] TRACK_USE_CACHE active\n", file));

			cached = true;

			// Let's use the cache
			m_readWrite.Flags = IRP_SYNCHRONOUS_API | IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
		}
		else if( !(file->Flags & FO_NO_INTERMEDIATE_BUFFERING) && CFilterBase::IsCached(file))
		{
			DBGPRINT(("ReadHeader: FO[0x%p] Flags[0x%x] is cached\n", file, file->Flags));
		
			// NERD ALERT: Be prepared that some strange component in the stack uses fake file objects 
			// for its work. It never makes sense to put RefCounted objects on the stack...
			if(!CFilterBase::IsStackBased(file))
			{
				cached = true;

				// Then let us use the cache
				m_readWrite.Flags = IRP_SYNCHRONOUS_API | IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
			}
			else
			{
				DBGPRINT(("ReadHeader -INFO: FO[0x%p] is stack-based, bypass cache\n", file));
			}
		}

		m_readWrite.Offset.QuadPart	= 0;
		m_readWrite.Length			= CFilterHeader::c_check;
		m_readWrite.Major			= IRP_MJ_READ;

		ASSERT(m_bufferSize >= m_readWrite.Length);
		status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

		if(NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;

			FILFILE_HEADER_BLOCK *block = (FILFILE_HEADER_BLOCK*) m_buffer;

			// Verify Header block
			if(FILF_POOL_TAG == block->Magic)
			{
				// Check Header's size parameters
				if((m_fileSize.QuadPart >= block->BlockSize) && 
				   (block->BlockSize >= sizeof(FILFILE_HEADER_BLOCK) + block->PayloadSize))
				{
					status = STATUS_SUCCESS;

					// Entire Header read?
					if(block->BlockSize > CFilterHeader::c_check)
					{
						// Buffer big enough?
						if(block->BlockSize <= m_bufferSize)
						{
							m_readWrite.Offset.LowPart = CFilterHeader::c_check;
							m_readWrite.Length		   = block->BlockSize - CFilterHeader::c_check;
							m_readWrite.Buffer		   = m_buffer + CFilterHeader::c_check;

							MmPrepareMdlForReuse(m_readWrite.Mdl);
							MmInitializeMdl(m_readWrite.Mdl, 
											m_readWrite.Buffer, 
											m_bufferSize - CFilterHeader::c_check);
							MmBuildMdlForNonPagedPool(m_readWrite.Mdl);
	
							// Read remaining parts of Header block
							ASSERT(m_bufferSize >= m_readWrite.Length);
							status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

							// Restore everything
							m_readWrite.Buffer = m_buffer;
							
							MmPrepareMdlForReuse(m_readWrite.Mdl);
							MmInitializeMdl(m_readWrite.Mdl,
											m_buffer, 
											m_bufferSize);
							MmBuildMdlForNonPagedPool(m_readWrite.Mdl);
						}
						else
						{
							m_readWrite.Length = block->BlockSize;

							// Allocate larger buffer
							status = Init(block->BlockSize);

							if(NT_SUCCESS(status))
							{
								if(cached)
								{
									// Keep using the cache
									m_readWrite.Flags = IRP_SYNCHRONOUS_API | IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
								}	

								// Read in complete new Header block
								ASSERT(m_bufferSize >= m_readWrite.Length);
								status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

								if(NT_SUCCESS(status))
								{
									block = (FILFILE_HEADER_BLOCK*) m_buffer;

									// Verify newly read Header block again
									if((FILF_POOL_TAG != block->Magic) ||
									   (block->BlockSize > m_fileSize.QuadPart) ||
									   (block->BlockSize < sizeof(FILFILE_HEADER_BLOCK) + block->PayloadSize))
									{
										status = STATUS_UNSUCCESSFUL;
									}
								}
							}
						}
					}
				}
				else
				{
					DBGPRINT(("ReadHeader -ERROR: invalid Header sizes, Block[0x%x] Payload[0x%x]\n", block->BlockSize, block->PayloadSize));	
				}
			}
		}

		if(cached && (file->Flags & FO_SYNCHRONOUS_IO))
		{
			file->CurrentByteOffset.QuadPart = 0;
		}

		// Restore potentially changed flags anyway
		m_readWrite.Flags = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::WriteHeader(FILE_OBJECT *file, CFilterHeader *header)
{
	ASSERT(file);
	ASSERT(header);

	PAGED_CODE();

	ASSERT(header->m_payloadSize);
	ASSERT(header->m_blockSize >= header->m_payloadSize);
	ASSERT(0 == (header->m_blockSize % CFilterHeader::c_align));
	ASSERT(header->m_key.m_size);
	ASSERT(header->m_key.m_cipher);

	ASSERT(m_extension);

	if(!m_fileSize.QuadPart)
	{
		// Retrieve current EOF
		CFilterBase::GetFileSize(m_extension->Lower, file, &m_fileSize);
	}

	NTSTATUS status = STATUS_SUCCESS;

	// Ensure correct EOF
	if(m_fileSize.QuadPart < header->m_blockSize)
	{
		m_fileSize.QuadPart = header->m_blockSize;

		// Set new EOF
		status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);
	}

	if(NT_SUCCESS(status))
	{
		status = Init(header->m_blockSize);

		if(NT_SUCCESS(status))
		{
			FILFILE_HEADER_BLOCK *const block = (FILFILE_HEADER_BLOCK*) m_buffer;

			m_readWrite.Offset.QuadPart	= 0;
			m_readWrite.Length			= header->m_blockSize;
			m_readWrite.Major			= IRP_MJ_WRITE;

			// Fill unused Header bytes with random data
			ASSERT(m_bufferSize >= header->m_blockSize);
			ASSERT(header->m_blockSize > sizeof(FILFILE_HEADER_BLOCK) + header->m_payloadSize);
			m_extension->Volume.m_context->Randomize((UCHAR*) block + sizeof(FILFILE_HEADER_BLOCK) + header->m_payloadSize, header->m_blockSize - (sizeof(FILFILE_HEADER_BLOCK) + header->m_payloadSize));

			// Set header block params
			block->Magic		= FILF_POOL_TAG;
			block->Version		= 1;
	       	// Copy cipher attributes from key
			block->Cipher		= header->m_key.m_cipher;
			block->BlockSize	= header->m_blockSize;
			block->PayloadSize	= header->m_payloadSize;
			block->PayloadCrc   = CFilterBase::Crc32(header->m_payload, header->m_payloadSize);
			block->Deepness		= header->m_deepness;
			block->Nonce		= header->m_nonce;

			// Copy Header Payload
			RtlCopyMemory((UCHAR*) block + sizeof(FILFILE_HEADER_BLOCK), header->m_payload, header->m_payloadSize);
			// Copy encrypted FileKey, copy always full 256 bits
			RtlCopyMemory((UCHAR*) &block->FileKey, header->m_key.m_key, sizeof(block->FileKey));

			DBGPRINT(("WriteHeader: new Header, Sizes(blk,pay)[0x%x, 0x%x] Nonce[0x%I64x] Deepness[0x%x]\n", block->BlockSize, block->PayloadSize, block->Nonce, block->Deepness));

			// Write Header
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_ERROR(status))
			{
				DBGPRINT(("WriteHeader -ERROR: HEADER write failed [0x%08x]\n", status));
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::RecognizeHeader(FILE_OBJECT *file, CFilterHeader *header, ULONG flags,FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(file);
	
	PAGED_CODE();

	ASSERT(m_extension);

	UCHAR* buffer=NULL;

	NTSTATUS status =STATUS_UNSUCCESSFUL;

	if (track && (track->State & TRACK_SHARE_DIRTORY))
	{
		status=CFilterControl::Callback().FireNotify(FILFILE_CONTROL_NULL,&buffer,0);
	}
	else
	{
		status = ReadHeader(file, flags);
	}

	if(NT_SUCCESS(status))
	{
		if (track)
		{
			if (buffer)
			{
				FILFILE_HEADER_BLOCK *const block = (FILFILE_HEADER_BLOCK*) buffer;
				//
				// TODO: use contained version info somehow
				//
				status = STATUS_UNSUCCESSFUL;

				// compute CRC of Header payload
				ULONG const crc = CFilterBase::Crc32(buffer + sizeof(FILFILE_HEADER_BLOCK), block->PayloadSize);

				if(crc == block->PayloadCrc)							
				{
					ASSERT(block->BlockSize > block->PayloadSize);
					ASSERT(block->BlockSize >= sizeof(CFilterHeader::c_align));

					status = STATUS_SUCCESS;

					ULONG keySize = 0;

					// Not an AutoConfig file?
					if(block->Cipher != (ULONG) FILFILE_CIPHER_SYM_AUTOCONF)
					{
						status = STATUS_UNSUCCESSFUL;

						// Ensure the cipher mode matches defined values
						if(HIWORD(block->Cipher) & FILFILE_CIPHER_MODE_MASK)
						{
							// Recognize symmetric cipher used and estimate FileKey size
							switch(LOWORD(block->Cipher))
							{
							case FILFILE_CIPHER_SYM_AES128:
								keySize = 16;
								status = STATUS_SUCCESS;
								break;
							case FILFILE_CIPHER_SYM_AES192:
								keySize = 24;
								status = STATUS_SUCCESS;
								break;
							case FILFILE_CIPHER_SYM_AES256:
								keySize = 32;
								status = STATUS_SUCCESS;
								break;
							default:
								ASSERT(false);
								break;
							}
						}
					}

					if(NT_SUCCESS(status))
					{
						DBGPRINT(("RecognizeHeader: valid Header, Sizes(blk,pay)[0x%x, 0x%x] Crc[0x%08x] Nonce[0x%I64x] Deepness[0x%x]\n", block->BlockSize, block->PayloadSize, crc, block->Nonce, block->Deepness));

						if(header)
						{
							// detect possible leaks文件头判断
							ASSERT(!header->m_payload);

							header->m_payloadSize	= block->PayloadSize;
							header->m_payloadCrc	= crc;
							header->m_blockSize		= block->BlockSize;
							header->m_deepness		= block->Deepness;
							header->m_nonce			= block->Nonce;  
							header->m_key.m_size    = keySize;

							if(keySize)
							{
								// Copy Cipher algo and mode used
								header->m_key.m_cipher = block->Cipher;
								// Copy encrypted FileKey, copy always full 256 bits
								RtlCopyMemory(header->m_key.m_key, &block->FileKey, sizeof(header->m_key.m_key));
							}

							// Client interested in Payload data?
							if( !(flags & TRACK_NO_PAYLOAD))
							{
								status = STATUS_INSUFFICIENT_RESOURCES;

								header->m_payload = (UCHAR*) ExAllocatePool(PagedPool, block->PayloadSize);

								if(header->m_payload)
								{
									RtlCopyMemory(header->m_payload, (UCHAR*) block + sizeof(FILFILE_HEADER_BLOCK), block->PayloadSize);

									status = STATUS_SUCCESS;
								}
							}
						}
					}
					else
					{
						DBGPRINT(("RecognizeHeader -WARN: invalid cipher [0x%x] used, ignore\n", block->Cipher));	
					}
				}
				else
				{
					DBGPRINT(("RecognizeHeader -ERROR: CRC32 mismatch, Header[0x%x] computed[0x%x]\n", block->PayloadCrc, crc));	
				}

				ExFreePool(buffer);
				buffer=0;
			}
		}
		else
		{
			FILFILE_HEADER_BLOCK *const block = (FILFILE_HEADER_BLOCK*) m_buffer;
			//
			// TODO: use contained version info somehow
			//
			status = STATUS_UNSUCCESSFUL;

			// compute CRC of Header payload
			ULONG const crc = CFilterBase::Crc32(m_buffer + sizeof(FILFILE_HEADER_BLOCK), block->PayloadSize);

			if(crc == block->PayloadCrc)							
			{
				ASSERT(block->BlockSize > block->PayloadSize);
				ASSERT(block->BlockSize >= sizeof(CFilterHeader::c_align));

				status = STATUS_SUCCESS;

				ULONG keySize = 0;

				// Not an AutoConfig file?
				if(block->Cipher != (ULONG) FILFILE_CIPHER_SYM_AUTOCONF)
				{
					status = STATUS_UNSUCCESSFUL;

					// Ensure the cipher mode matches defined values
					if(HIWORD(block->Cipher) & FILFILE_CIPHER_MODE_MASK)
					{
						// Recognize symmetric cipher used and estimate FileKey size
						switch(LOWORD(block->Cipher))
						{
						case FILFILE_CIPHER_SYM_AES128:
							keySize = 16;
							status = STATUS_SUCCESS;
							break;
						case FILFILE_CIPHER_SYM_AES192:
							keySize = 24;
							status = STATUS_SUCCESS;
							break;
						case FILFILE_CIPHER_SYM_AES256:
							keySize = 32;
							status = STATUS_SUCCESS;
							break;
						default:
							ASSERT(false);
							break;
						}
					}
				}

				if(NT_SUCCESS(status))
				{
					DBGPRINT(("RecognizeHeader: valid Header, Sizes(blk,pay)[0x%x, 0x%x] Crc[0x%08x] Nonce[0x%I64x] Deepness[0x%x]\n", block->BlockSize, block->PayloadSize, crc, block->Nonce, block->Deepness));

					if(header)
					{
						// detect possible leaks文件头判断
						ASSERT(!header->m_payload);

						header->m_payloadSize	= block->PayloadSize;
						header->m_payloadCrc	= crc;
						header->m_blockSize		= block->BlockSize;
						header->m_deepness		= block->Deepness;
						header->m_nonce			= block->Nonce;  
						header->m_key.m_size    = keySize;

						if(keySize)
						{
							// Copy Cipher algo and mode used
							header->m_key.m_cipher = block->Cipher;
							// Copy encrypted FileKey, copy always full 256 bits
							RtlCopyMemory(header->m_key.m_key, &block->FileKey, sizeof(header->m_key.m_key));
						}

						// Client interested in Payload data?
						if( !(flags & TRACK_NO_PAYLOAD))
						{
							status = STATUS_INSUFFICIENT_RESOURCES;

							header->m_payload = (UCHAR*) ExAllocatePool(PagedPool, block->PayloadSize);

							if(header->m_payload)
							{
								RtlCopyMemory(header->m_payload, (UCHAR*) block + sizeof(FILFILE_HEADER_BLOCK), block->PayloadSize);

								status = STATUS_SUCCESS;
							}
						}
					}
				}
				else
				{
					DBGPRINT(("RecognizeHeader -WARN: invalid cipher [0x%x] used, ignore\n", block->Cipher));	
				}
			}
			else
			{
				DBGPRINT(("RecognizeHeader -ERROR: CRC32 mismatch, Header[0x%x] computed[0x%x]\n", block->PayloadCrc, crc));	
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if FILFILE_USE_PADDING

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::UpdateTail(FILE_OBJECT *file, CFilterContextLink *link, LARGE_INTEGER *fileSize)
{
	ASSERT(file);
	ASSERT(link);
	ASSERT(fileSize);

	// Update Tail if file was truncated - its size is correct but the Padding (and Filler) just was cut off.
	PAGED_CODE();

	ASSERT(m_extension);

	// ensure we can do our job
	ASSERT(link->m_headerBlockSize);
	ASSERT(link->m_nonce.QuadPart);
	ASSERT(link->m_fileKey.m_size);

	ASSERT(fileSize->QuadPart);

	m_fileSize = *fileSize;

	// check file sizes
	if(m_fileSize.QuadPart < link->m_headerBlockSize + CFilterContext::c_tail)
	{
		DBGPRINT(("UpdateTail -ERROR: file invalid\n"));
 
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = Init(CFilterBase::c_sectorSize);

	if(NT_SUCCESS(status))
	{
		ULONG const filler  = CFilterContext::ComputeFiller(m_fileSize.LowPart);
		ULONG const padding = CFilterContext::c_blockSize - filler;

		DBGPRINT(("UpdateTail: FO[0x%p] Padding[0x%x] Filler[0x%x]\n", file, padding, filler));

		// remove Filler
		m_fileSize.QuadPart -= filler;
		
		m_readWrite.Offset	 = m_fileSize;
		m_readWrite.Length	 = CFilterBase::c_sectorSize;
		m_readWrite.Major	 = IRP_MJ_READ;

		// ensure sector alignment
		if(m_readWrite.Offset.LowPart & (CFilterBase::c_sectorSize - 1))
		{
			// round down to sector boundary
			m_readWrite.Offset.LowPart &= -CFilterBase::c_sectorSize;
		}
		else
		{
			ASSERT(m_readWrite.Offset.QuadPart >= CFilterBase::c_sectorSize);
			m_readWrite.Offset.QuadPart -= CFilterBase::c_sectorSize;
		}

		FILFILE_CRYPT_CONTEXT crypt;
		RtlZeroMemory(&crypt, sizeof(crypt));

		crypt.Nonce			   = link->m_nonce;
		crypt.Offset.QuadPart  = m_readWrite.Offset.QuadPart - link->m_headerBlockSize;
		crypt.Key			   = link->m_fileKey;

		// compute valid bytes in last sector
		ULONG valid = m_fileSize.LowPart & (CFilterBase::c_sectorSize - 1);

		if(!valid)
		{
			valid = CFilterBase::c_sectorSize;
		}

		// Check whether Tail isn't a full block of Padding. If so, no need to read it
		if(padding < CFilterContext::c_blockSize)
		{
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_SUCCESS(status))
			{
				// Decrypt valid bytes, w/o Filler
				CFilterContext::Decode(m_buffer, valid, &crypt);
			}
		}
		else
		{
			ASSERT(padding == CFilterContext::c_blockSize);
		}

		if(NT_SUCCESS(status))
		{
			// Update Padding. Overwrite data that is now beyond EOF
			ASSERT(valid >= padding);
			CFilterContext::AddPadding(m_buffer, valid - padding);

			// Encrypt valid bytes again
			CFilterContext::Encode(m_buffer, valid, &crypt);

			m_readWrite.Major = IRP_MJ_WRITE;

			// Write sector back
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_ERROR(status))
			{
				DBGPRINT(("UpdateTail: write back failed [0x%08x]\n", status));
			}
		}
		else
		{
			DBGPRINT(("UpdateTail: couldn't read last sector [0x%08x]\n", status));
		}

		// be paranoid
		RtlZeroMemory(m_buffer, valid);
		RtlZeroMemory(&crypt, sizeof(crypt));
	}

	return status;
}

#endif // FILFILE_USE_PADDING
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if FILFILE_USE_PADDING

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::RetrieveTail(FILE_OBJECT *file, CFilterHeader *header, ULONG *tail)
{
	ASSERT(file);
	ASSERT(header);

	PAGED_CODE();

	ASSERT(m_extension);
         
	// The Header should be already detected
	ASSERT(header->m_blockSize);
	ASSERT(header->m_nonce.QuadPart);
	ASSERT(header->m_key.m_cipher);
	ASSERT(header->m_key.m_size);

	if(!m_fileSize.QuadPart)
	{
		// Get current EOF
		CFilterBase::GetFileSize(m_extension->Lower, file, &m_fileSize);
	}

	// Zero sized files have no Tail at all
	if(m_fileSize.QuadPart == header->m_blockSize)
	{
		DBGPRINT(("RetrieveTail -INFO: zero sized file, no Tail\n"));

		if(tail)
		{
			*tail = 0;
		}
        
		return STATUS_SUCCESS;
	}
	// Check file sizes
	if(m_fileSize.QuadPart < header->m_blockSize + CFilterContext::c_tail)
	{
		DBGPRINT(("RetrieveTail -ERROR: file invalid\n"));
 
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status = Init(CFilterBase::c_sectorSize);

	if(NT_SUCCESS(status))
	{
		// Compute default values
		ULONG padded	   = CFilterContext::ComputePadding(m_fileSize.LowPart);
		ULONG const filler = CFilterContext::ComputeFiller(m_fileSize.LowPart);
		
		// Remove Filler prior Padding verification
		m_fileSize.QuadPart -= filler;
		
		m_readWrite.Offset	 = m_fileSize;
		m_readWrite.Length	 = CFilterBase::c_sectorSize;
		m_readWrite.Major	 = IRP_MJ_READ;

		// Ensure sector alignment
		if(m_readWrite.Offset.LowPart & (CFilterBase::c_sectorSize - 1))
		{
			// Round down to sector boundary
			m_readWrite.Offset.LowPart &= -CFilterBase::c_sectorSize;
		}
		else
		{
			ASSERT(m_readWrite.Offset.QuadPart >= CFilterBase::c_sectorSize);
			m_readWrite.Offset.QuadPart -= CFilterBase::c_sectorSize;
		}
																									
		status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

		if(NT_SUCCESS(status))
		{
			FILFILE_CRYPT_CONTEXT crypt;
			RtlZeroMemory(&crypt,  sizeof(crypt));

			crypt.Nonce			   = header->m_nonce;
			crypt.Offset.QuadPart  = m_readWrite.Offset.QuadPart - header->m_blockSize;
			crypt.Key			   = header->m_key;

			// Compute valid bytes in last sector
			ULONG valid = m_fileSize.LowPart & (CFilterBase::c_sectorSize - 1);

			if(!valid)
			{
				valid = CFilterBase::c_sectorSize;
			}
			
			// Decrypt valid bytes, w/o Filler
			CFilterContext::Decode(m_buffer, valid, &crypt);

			// Verify the Padding
			padded = CFilterContext::GetPadding(m_buffer, valid);

			if(padded)
			{
				DBGPRINT(("RetrieveTail: valid, Padding[0x%x] Filler[0x%x]\n", padded, filler));
			}
			else
			{
				DBGPRINT(("RetrieveTail -ERROR: Padding invalid\n"));

				status = STATUS_UNSUCCESSFUL;
			}
	
			// be paranoid
			RtlZeroMemory(m_buffer, valid);
			RtlZeroMemory(&crypt, sizeof(crypt));
		}
		else
		{
			DBGPRINT(("RetrieveTail: couldn't read last sector [0x%08x]\n", status));
		}

		if(NT_ERROR(status) && (m_flags & FILFILE_CONTROL_RECOVER))
		{
			// Recovery mode, use computed values
			DBGPRINT(("RetrieveTail: Recovery mode enabled, proceeding\n"));

			status = STATUS_SUCCESS;
		}

		if(NT_SUCCESS(status))
		{
			if(tail)
			{
				// Create Tail (Padded | Filler)
				*tail = MAKELONG(padded, filler);

				// Ensure Tail property
				ASSERT(HIWORD(*tail) + LOWORD(*tail) == CFilterContext::c_tail);
			}
		}

		// Restore EOF
		m_fileSize.QuadPart += filler;
	}

	return status;
}

#endif // FILFILE_USE_PADDING
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::ProcessFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *read, FILFILE_TRACK_CONTEXT *write)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(!write || (write && write->Header.m_blockSize));

	// Ensure that Tail always fits in our buffer
	C_ASSERT(CFilterBase::c_sectorSize >= CFilterContext::c_tail);

	// Init buffers with enough room for maximum buffer plus additional sector
	NTSTATUS status = Init(MM_MAXIMUM_DISK_IO_SIZE + CFilterBase::c_sectorSize);

	if(NT_SUCCESS(status))
	{
		// Initialize current EOF
		status = CFilterBase::GetFileSize(m_extension->Lower, file, &m_fileSize);

		if(NT_SUCCESS(status))
		{
			// Compute distance the existing file data need to be moved, if at all
			LONG distance = 0;

			if(write)
			{
				distance = (LONG) write->Header.m_blockSize;
			}

			if(read)
			{
				distance -= (LONG) read->Header.m_blockSize;
			}

			// Dispatch on distance
			if(distance > 0)
			{
				ASSERT(write);

				// Ignore zero sized files
				if(m_fileSize.QuadPart)
				{
					status = ProcessFileUp(file, read, write, distance);
				}
			}
			else
			{
				ASSERT(read);
				
				// Just remove Header w/o any data?
				if(!write && (m_fileSize.QuadPart == read->Header.m_blockSize))
				{
					m_fileSize.QuadPart = 0;

					// Set final EOF
					status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);
				}
				else
				{
					status = ProcessFileEqualDown(file, read, write, distance);
				}
			}

			if(m_buffer)
			{
				ASSERT(m_bufferSize);
				// be paranoid
				RtlZeroMemory(m_buffer, m_bufferSize);
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::ProcessFileUp(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *read, FILFILE_TRACK_CONTEXT *write, LONG distance)
{
	ASSERT(file);
	ASSERT(write);
	
	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(m_fileSize.QuadPart);
	ASSERT(m_buffer && m_bufferSize);
	ASSERT(m_bufferSize >= MM_MAXIMUM_DISK_IO_SIZE);

	ASSERT(distance > 0);
	ASSERT(write->Header.m_payloadSize);
	ASSERT(write->Header.m_blockSize);
	ASSERT(!read || (write->Header.m_blockSize > read->Header.m_blockSize));

	NTSTATUS status		= STATUS_SUCCESS;

	ULONG offsetShift	= 0;
	ULONG eofShift		= 0;

	ULONG tail			= 0;
	ULONG filler		= 0;

	LARGE_INTEGER bytesTotal = m_fileSize;
	
#if FILFILE_USE_PADDING
	tail = CFilterContext::c_tail;

	// Process already encrypted file?
	if(read)
	{
		// Save existing Block size
		offsetShift = read->Header.m_blockSize;

		if(read->Header.m_key.m_size)
		{
			// Ensure file validity by decrypting and verifying the Padding, get Tail
			status = RetrieveTail(file, &read->Header, &tail);

			if(NT_ERROR(status))
			{
				return status;
			}

			// Save Filler's size
			filler = LOWORD(tail);
			ASSERT(filler <= CFilterContext::c_tail);

			tail = CFilterContext::c_tail;
		}
	}
	else
	{
		// If we initally encrypt a file, add Tail (Filler + Padding) to final EOF
		m_fileSize.QuadPart += tail;
	}
#endif
	
	// Add Header (distance) to final EOF
	m_fileSize.QuadPart += distance;
		
	if(m_fileSize.LowPart & (CFilterBase::c_sectorSize - 1))
	{	
		eofShift = CFilterBase::c_sectorSize - (m_fileSize.LowPart & (CFilterBase::c_sectorSize - 1));
		ASSERT(eofShift < CFilterBase::c_sectorSize);

		DBGPRINT(("ProcessFileUp: Extend EOF by [0x%x]\n", eofShift));

		// On Vista with SMB 2.0, all write requests must be a multiple of the sector size, but a request cannot exceed 
		// EOF. So we have to extend EOF temporarily so that such writes will succeed and truncate the file later - Aaargh.
		m_fileSize.QuadPart += eofShift;			
	}

	ASSERT(0 == (m_fileSize.LowPart & (CFilterBase::c_sectorSize - 1)));

	// Set intermediate EOF
	status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);

	if(NT_ERROR(status))
	{
		DBGPRINT(("ProcessFileUp -ERROR: SetFileInfo(I) failed [0x%08x]\n", status));

		return status;
	}

	FILFILE_CRYPT_CONTEXT cryptRead, cryptWrite;
	RtlZeroMemory(&cryptWrite, sizeof(cryptWrite));
	RtlZeroMemory(&cryptRead,  sizeof(cryptRead));
	
	// Init the crypt contexts for read/write
	if(read && read->Header.m_key.m_size)
	{
		ASSERT(read->EntityKey.m_cipher == read->Header.m_key.m_cipher);

		cryptRead.Nonce = read->Header.m_nonce;
		cryptRead.Key   = read->Header.m_key;
	}

	if(write->Header.m_key.m_size)
	{
		ASSERT(write->EntityKey.m_cipher == write->Header.m_key.m_cipher);

		cryptWrite.Nonce = write->Header.m_nonce;
		cryptWrite.Key   = write->Header.m_key;
	}

	DBGPRINT(("ProcessFileUp: current EOF[0x%I64x] move UP by [0x%x]\n", bytesTotal, distance));
	
	if(offsetShift)
	{
		// If we have existing meta data (Block size, Filler), ignore it
		ASSERT(bytesTotal.QuadPart >= offsetShift + filler);
		bytesTotal.QuadPart -= offsetShift + filler;
	}

	// Round down to buffer boundary
	ULONG bytes = bytesTotal.LowPart & (MM_MAXIMUM_DISK_IO_SIZE - 1);

	if(!bytes)
	{
		bytes = MM_MAXIMUM_DISK_IO_SIZE;
	}

	if(NT_SUCCESS(status))
	{
		while(bytesTotal.QuadPart)
		{
			ASSERT(bytes <= MM_MAXIMUM_DISK_IO_SIZE);
			ASSERT(bytesTotal.QuadPart >= bytes);

			// Save cooked offset
			LARGE_INTEGER offsetCrypt   = bytesTotal;
			offsetCrypt.QuadPart	   -= bytes;

			m_readWrite.Offset.QuadPart = offsetCrypt.QuadPart + offsetShift;
			m_readWrite.Length			= bytes;
			m_readWrite.Major			= IRP_MJ_READ;

			ASSERT(m_bufferSize >= bytes);
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_ERROR(status))
			{
				DBGPRINT(("ProcessFileUp -ERROR: DATA(o,s)[0x%I64x,0x%x] read failed [0x%08x]\n", m_readWrite.Offset, m_readWrite.Length, status));
				break;
			}

			if(cryptRead.Key.m_size)
			{
				cryptRead.Offset = offsetCrypt;
				// Decode buffer
				ASSERT(m_bufferSize >= m_readWrite.Length);
				CFilterContext::Decode(m_buffer, m_readWrite.Length, &cryptRead);
			}
			
			if(cryptWrite.Key.m_size)
			{
				cryptWrite.Offset = offsetCrypt;

				ULONG encode = m_readWrite.Length;

				if(tail)
				{
					ASSERT(CFilterContext::c_tail == tail);

					if(offsetShift)
					{
						// Even if file is already padded, compute Padding and Filler
						ASSERT(encode >= tail - filler);
						encode -= tail - filler;
					}

					ASSERT(m_bufferSize >= encode + tail);
					encode += m_extension->Volume.m_context->AddPaddingFiller(m_buffer, encode);
					
					m_readWrite.Length += tail;

					// Add Padding/Filler only once
					tail = 0;
				}

				// Encode buffer
				ASSERT(m_bufferSize >= encode);
				CFilterContext::Encode(m_buffer, encode, &cryptWrite);
			}

			m_readWrite.Offset.QuadPart += distance;
			m_readWrite.Major			 = IRP_MJ_WRITE;

			// Align on sector boundary
			m_readWrite.Length = (m_readWrite.Length + (CFilterBase::c_sectorSize - 1)) & ~(CFilterBase::c_sectorSize - 1);
			ASSERT(m_bufferSize >= m_readWrite.Length);
				
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_ERROR(status))
			{
				DBGPRINT(("ProcessFileUp -ERROR: DATA(o,s)[0x%I64x,0x%x] write failed [0x%08x]\n", m_readWrite.Offset, m_readWrite.Length, status));
				break;
			}

			bytesTotal.QuadPart -= bytes;

			bytes = MM_MAXIMUM_DISK_IO_SIZE;

			if(!bytesTotal.HighPart && (bytesTotal.LowPart < MM_MAXIMUM_DISK_IO_SIZE))
			{
				bytes = bytesTotal.LowPart;
			}
		};
	}

	// Do we have EOF extended temporarily?
	if(eofShift)
	{
		ASSERT(m_fileSize.QuadPart > eofShift);

		// Compute final EOF
		m_fileSize.QuadPart -= eofShift;

		// Set final EOF
		status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);

		if(NT_ERROR(status))
		{
			DBGPRINT(("ProcessFileUp -ERROR: SetFileSize(II) failed [0x%08x]\n", status));
		}
	}

	// be paranoid
	RtlZeroMemory(&cryptRead,  sizeof(cryptRead));
	RtlZeroMemory(&cryptWrite, sizeof(cryptWrite));
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::ProcessFileEqualDown(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *read, FILFILE_TRACK_CONTEXT *write, LONG distance)
{
	ASSERT(file);
	ASSERT(read);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(m_fileSize.QuadPart);
	ASSERT(m_buffer && m_bufferSize);
	ASSERT(m_bufferSize >= MM_MAXIMUM_DISK_IO_SIZE);

	ASSERT(distance <= 0);
	ASSERT(read->Header.m_blockSize);
	ASSERT(!write || (read->Header.m_blockSize >= write->Header.m_blockSize));

	NTSTATUS status = STATUS_SUCCESS;
	ULONG tail		= 0;

#if FILFILE_USE_PADDING
	if(read->Header.m_key.m_size)
	{
		// Ensure file validity by decrypting/verifying the Padding and get Tail
		status = RetrieveTail(file, &read->Header, &tail);

		if(NT_ERROR(status))
		{
			return status;
		}

		// Ignore Filler from now on
		m_fileSize.QuadPart -= LOWORD(tail);
	}
#endif

	FILFILE_CRYPT_CONTEXT cryptRead, cryptWrite;
	RtlZeroMemory(&cryptWrite, sizeof(cryptWrite));
	RtlZeroMemory(&cryptRead,  sizeof(cryptRead));

	// Init the crypt contexts for read/write
	if(read->Header.m_key.m_size)
	{
		ASSERT(read->EntityKey.m_cipher == read->Header.m_key.m_cipher);

		cryptRead.Nonce = read->Header.m_nonce;
		cryptRead.Key   = read->Header.m_key;
	}

	if(write && write->Header.m_key.m_size)
	{
		ASSERT(write->EntityKey.m_cipher == write->Header.m_key.m_cipher);

		cryptWrite.Nonce = write->Header.m_nonce;
		cryptWrite.Key   = write->Header.m_key;
	}

	DBGPRINT(("ProcessFileEqualDown: current EOF[0x%I64x] move DOWN by [0x%x], Tail[0x%x]\n", m_fileSize, distance, CFilterContext::c_tail));

	// Make absolute
	distance = -distance;

	// Start right after Header block
	m_readWrite.Offset.QuadPart = read->Header.m_blockSize;

	while(m_readWrite.Offset.QuadPart < m_fileSize.QuadPart)
	{
		ULONG bytes = (ULONG) (m_fileSize.QuadPart - m_readWrite.Offset.QuadPart);

		if(!bytes || (bytes > MM_MAXIMUM_DISK_IO_SIZE))
		{
			bytes = MM_MAXIMUM_DISK_IO_SIZE;
		}

		m_readWrite.Length = bytes;
		m_readWrite.Major  = IRP_MJ_READ;

		ASSERT(m_readWrite.Offset.QuadPart >= read->Header.m_blockSize);
		// Save cooked offset
		LARGE_INTEGER offsetCrypt  = m_readWrite.Offset;
		offsetCrypt.QuadPart	  -= read->Header.m_blockSize;

		ASSERT(m_readWrite.Length <= MM_MAXIMUM_DISK_IO_SIZE);
															
		ASSERT(m_bufferSize >= m_readWrite.Length);
		status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

		if(NT_SUCCESS(status))
		{
			if(cryptRead.Key.m_size)
			{
				cryptRead.Offset = offsetCrypt;
				// Decode buffer
				ASSERT(m_bufferSize >= bytes);
				CFilterContext::Decode(m_buffer, bytes, &cryptRead);
			}

			if(cryptWrite.Key.m_size)
			{
				cryptWrite.Offset = offsetCrypt;
				// Encode buffer
				ASSERT(m_bufferSize >= bytes);
				CFilterContext::Encode(m_buffer, bytes, &cryptWrite);
			}

			ASSERT(m_readWrite.Offset.QuadPart >= distance);

			// Align on sector boundary, otherwise NTFS will barf (sometimes) ...
			m_readWrite.Offset.QuadPart -= distance;
			m_readWrite.Length		     = (bytes + (CFilterBase::c_sectorSize - 1)) & ~(CFilterBase::c_sectorSize - 1);
			m_readWrite.Major			 = IRP_MJ_WRITE;
				
			status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

			if(NT_ERROR(status))
			{
				DBGPRINT(("ProcessFileEqualDown -ERROR: DATA(o,s)[0x%I64x,0x%x] write failed [0x%08x]\n", m_readWrite.Offset, bytes, status));
			}
		}
		else
		{
			DBGPRINT(("ProcessFileEqualDown -ERROR: DATA(o,s)[0x%I64x,0x%x] read failed [0x%08x]\n", m_readWrite.Offset, bytes, status));
		}

		if(NT_ERROR(status) && (m_flags & FILFILE_CONTROL_RECOVER))
		{
			// In recovery mode, ignore read/write errors
			DBGPRINT(("ProcessFileEqualDown -WARN: recovery mode enabled, proceeding\n"));

			status = STATUS_SUCCESS;
		}

		m_readWrite.Offset.QuadPart += distance + bytes;
	};
    
	if(NT_SUCCESS(status) && distance)
	{
		// Restore EOF
		m_fileSize.QuadPart += LOWORD(tail);

		// Cut off Header block
		m_fileSize.QuadPart -= distance;
		
		// Decrypting?
		if(distance == read->Header.m_blockSize)
		{
			// Cut off Tail (Filler + Padding)
			m_fileSize.QuadPart -= CFilterContext::c_tail;
		}

		// Set final EOF
		status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);

		if(NT_ERROR(status))
		{
			DBGPRINT(("ProcessFileEqualDown -ERROR: SetFileInfo(EOF) failed [0x%08x]\n", status));
		}
	}

	// be paranoid
	RtlZeroMemory(&cryptRead,  sizeof(cryptRead));
	RtlZeroMemory(&cryptWrite, sizeof(cryptWrite));
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::AutoConfigPost(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_extension);

	NTSTATUS status = STATUS_SUCCESS;

	// Is data file valid?
	if(m_fileSize.QuadPart)
	{
		FILE_BASIC_INFORMATION basicInfo;
		RtlZeroMemory(&basicInfo, sizeof(basicInfo));

		// Get the file attributes
		status = CFilterBase::QueryFileInfo(m_extension->Lower, file, FileBasicInformation, &basicInfo, sizeof(basicInfo));

		if(NT_SUCCESS(status))
		{
			// Should we update?
			if( !(basicInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM))
			{
				DBGPRINT(("AutoConfPost: update file attributes\n"));
					
				basicInfo.FileAttributes |= FILE_ATTRIBUTE_SYSTEM;

				status = CFilterBase::SetFileInfo(m_extension->Lower, file, FileBasicInformation, &basicInfo, sizeof(basicInfo));

				if(NT_ERROR(status))
				{
					DBGPRINT(("AutoConfPost -ERROR: SetFileInfo(FileBasicInformation) failed [0x%08x]\n", status));
				}
			}
		}
		else
		{
			DBGPRINT(("AutoConfPost -ERROR: QueryFileInfo(FileBasicInformation) failed [0x%08x]\n", status));
		}
	}
	else
	{
		DBGPRINT(("AutoConf: delete ZERO sized file\n"));

		FILE_DISPOSITION_INFORMATION dispInfo = {true};

		// Delete file
		status = CFilterBase::SetFileInfo(m_extension->Lower, file, FileDispositionInformation, &dispInfo, sizeof(dispInfo));

		if(NT_ERROR(status))
		{
			DBGPRINT(("AutoConfPost -ERROR: SetFileInfo(FileDispositionInformation) failed [0x%08x]\n", status));
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::AutoConfigRead(FILE_OBJECT *file, CFilterHeader *header, ULONG flags,FILFILE_TRACK_CONTEXT *track)
{
	//ASSERT(file);
	//ASSERT(header);
	
	PAGED_CODE();

	//ASSERT(m_extension);
	//ASSERT(!header->m_payload);

	// Try to get common Header
	NTSTATUS status = RecognizeHeader(file, header, flags | TRACK_USE_CACHE,track);

	if(NT_SUCCESS(status))
	{
		if (!track)
		{
			status = STATUS_UNSUCCESSFUL;
			FILFILE_HEADER_BLOCK *const block = (FILFILE_HEADER_BLOCK*) m_buffer;

			// Ensure that we really have an AutoConfig file, instead of an encrypted data file
			if(block && block->Cipher == (ULONG) FILFILE_CIPHER_SYM_AUTOCONF)
			{
				status = STATUS_SUCCESS;
			}
			else
			{
				DBGPRINT(("AutoConfigRead -INFO: valid Header, but no AutoConfig file\n"));
			}
		}
	}
	else
	{
		DBGPRINT(("AutoConfigRead -INFO: no Header at all\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCipherManager::AutoConfigWrite(FILE_OBJECT *file, CFilterHeader *header)//生成配置文件
{
	ASSERT(file);
	ASSERT(header);

	PAGED_CODE();

	ASSERT(m_extension);
    
	NTSTATUS status = STATUS_SUCCESS;

	// Delete AutoConfig file? 
	if(!header->m_payloadSize)
	{
		// So delete it
		FILE_DISPOSITION_INFORMATION dispInfo = {true};
			
		status = CFilterBase::SetFileInfo(m_extension->Lower, file, FileDispositionInformation, &dispInfo, sizeof(dispInfo));

		if(NT_SUCCESS(status))
		{
			DBGPRINT(("AutoConfigWrite: has been deleted\n"));
		}

		return status;
	}

	ASSERT(header->m_payload);
	ASSERT(header->m_payloadSize);

	// Compute size of (aligned) Header block
	header->m_blockSize = (sizeof(FILFILE_HEADER_BLOCK) + header->m_payloadSize + (CFilterHeader::c_align - 1)) & ~(CFilterHeader::c_align - 1);

	// Size of Header should never exceed 4GB
	m_fileSize.QuadPart = header->m_blockSize;
		
	// Set final EOF
	status = CFilterBase::SetFileSize(m_extension->Lower, file, &m_fileSize);

	if(NT_ERROR(status))
	{
		return status;
	}

	status = Init(m_fileSize.LowPart);

	if(NT_SUCCESS(status))
	{
		m_readWrite.Length			= m_fileSize.LowPart;
		m_readWrite.Offset.QuadPart	= 0;
		m_readWrite.Flags			= IRP_SYNCHRONOUS_API | IRP_WRITE_OPERATION | IRP_DEFER_IO_COMPLETION;
		m_readWrite.Major			= IRP_MJ_WRITE;
				
		ASSERT(header->m_blockSize > header->m_payloadSize);

		// Fill unused Header parts with (simple) random data
		m_extension->Volume.m_context->Randomize(m_buffer,  sizeof(FILFILE_HEADER_BLOCK));

		ULONG const valid = sizeof(FILFILE_HEADER_BLOCK) + header->m_payloadSize;

		m_extension->Volume.m_context->Randomize(m_buffer + valid, m_fileSize.LowPart - valid);

		FILFILE_HEADER_BLOCK *const block = (FILFILE_HEADER_BLOCK*) m_buffer;

		// Init Header block params
		block->Magic		= FILF_POOL_TAG;
		block->Version		= 1;
		block->Cipher		= FILFILE_CIPHER_SYM_AUTOCONF;
		block->BlockSize	= header->m_blockSize;
		block->PayloadSize	= header->m_payloadSize;
		block->PayloadCrc   = CFilterBase::Crc32(header->m_payload, header->m_payloadSize);
		block->Deepness		= header->m_deepness;
					
		// Copy Header Payload
		RtlCopyMemory(m_buffer + sizeof(FILFILE_HEADER_BLOCK), header->m_payload, header->m_payloadSize);

		DBGPRINT(("AutoConfigWrite: Sizes(blk,pay)[0x%x,0x%x] Deepness[0x%x]\n", block->BlockSize, block->PayloadSize, block->Deepness));

		// Write Header
		status = CFilterBase::ReadWrite(m_extension->Lower, file, &m_readWrite);

		if(NT_SUCCESS(status))
		{
			ASSERT(m_fileSize.QuadPart);

			// Common post processing for AutoConfig files
			AutoConfigPost(file);
		}
		else
		{
			DBGPRINT(("AutoConfigWrite -ERROR: write failed [0x%08x]\n", status));
		}

		m_readWrite.Flags  = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	}
    
	return status;
}
    
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
