////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterPath.cpp: implementation of the CFilterPath class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterPath.h"
#include "CFilterControl.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::Build(LPCWSTR path, ULONG pathLength, UNICODE_STRING const* prefix)
{
	ASSERT(path);
	ASSERT(pathLength);

	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	ULONG bufferSize = pathLength + (3 * sizeof(WCHAR));

	if(prefix)
	{
		bufferSize += prefix->Length;
	}

	LPWSTR buffer = (LPWSTR) ExAllocatePool(PagedPool, bufferSize);	

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG curr = 0;

	if(prefix)
	{
		RtlCopyMemory(buffer, prefix->Buffer, prefix->Length);

		curr += prefix->Length / sizeof(WCHAR);

		if(path[0] != L'\\')
		{
			buffer[curr] = L'\\';
			curr++;
		}
	}

	RtlCopyMemory(buffer + curr, path, pathLength);

	curr += pathLength / sizeof(WCHAR);

	ASSERT(bufferSize > curr * sizeof(WCHAR));
	RtlZeroMemory(buffer + curr, bufferSize - (curr * sizeof(WCHAR)));

	m_volume	   = (LPWSTR) buffer;
	m_volumeLength = (USHORT) curr * sizeof(WCHAR);
	
	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::Init(LPCWSTR path, ULONG pathLength, ULONG type, UNICODE_STRING const* device)
{
	ASSERT(path);
	ASSERT(pathLength);

	if(!path || !pathLength)
	{
		return STATUS_INVALID_PARAMETER;
	}

	PAGED_CODE();

	UNICODE_STRING const* prefix = device;

	if(type & FILFILE_DEVICE_REDIRECTOR)
	{
		prefix = 0;
	}

	NTSTATUS status = Build(path, pathLength, prefix);

	if(NT_SUCCESS(status))
	{
		ASSERT(m_volume);
		ASSERT(m_volumeLength);

		if(prefix)
		{
			// Volume based device
			m_volumeLength	   = prefix->Length;
			m_directory		   = m_volume + (m_volumeLength / sizeof(WCHAR));
			m_directoryLength  = (USHORT) pathLength;
		}

		// Have composite path parsed
		status = Parse(type);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::InitClient(LPCWSTR path, ULONG pathLength, ULONG pathFlags)
{
	ASSERT(path);
	ASSERT(pathLength);

	PAGED_CODE();

	// Transform to char count
	pathLength /= sizeof(WCHAR);

	// Strip trailing zeros
	while(pathLength > 1)
	{
		if(path[pathLength - 1])
		{
			break;
		}

		pathLength--;
	}

	RtlZeroMemory(this, sizeof(*this));

	// Parse device name, ignore errors

	ULONG deviceType = FILFILE_DEVICE_NULL;
	UNICODE_STRING deviceName = {0,0,0};

	CFilterBase::ParseDeviceName(path, pathLength * sizeof(WCHAR), &deviceName, &deviceType);
	
	ULONG pathStart = deviceName.Length / sizeof(WCHAR);

	if(deviceType & FILFILE_DEVICE_REDIRECTOR)
	{
		pathLength -= pathStart;
	}

	// Allocate storage for termination and a trailing backslash
	ULONG  const bufferSize = (pathLength + 1 + 1) * sizeof(WCHAR);
	UCHAR *const buffer	    = (UCHAR*) ExAllocatePool(PagedPool, bufferSize);	

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Transform back to byte size
	pathLength *= sizeof(WCHAR);

	if(deviceType & FILFILE_DEVICE_REDIRECTOR)
	{
		RtlCopyMemory(buffer, path + pathStart, pathLength);

		m_volume	   = (LPWSTR) buffer;
		m_volumeLength = (USHORT) pathLength;
	}
	else if(deviceType & FILFILE_DEVICE_VOLUME)
	{
		RtlCopyMemory(buffer, path, pathLength);

		m_volume	   = (LPWSTR) buffer;
		m_volumeLength = (USHORT) (pathStart * sizeof(WCHAR));

		m_directory		   = (LPWSTR) (buffer + m_volumeLength);
		m_directoryLength  = (USHORT) (pathLength - m_volumeLength);
	}
	else
	{
		// Default, if device parsing has failed
		RtlCopyMemory(buffer, path, pathLength);

		m_directory		   = (LPWSTR) buffer;
		m_directoryLength  = (USHORT) pathLength;
	}

	ASSERT(bufferSize > pathLength);
	RtlZeroMemory(buffer + pathLength, bufferSize - pathLength);

	// Have path parsed
	return Parse(deviceType, pathFlags);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::Parse(ULONG type, ULONG pathFlags)
{
	PAGED_CODE();

	ASSERT(m_volume || m_directory || m_file);
	ASSERT(m_volumeLength || m_directoryLength || m_fileLength);

	LONG len   = 0;
	LONG index = 0;

	if(type & FILFILE_DEVICE_REDIRECTOR)
	{
		switch(type & FILFILE_DEVICE_REDIRECTOR)
		{
			case FILFILE_DEVICE_REDIRECTOR_CIFS:
				m_flags |= TRACK_CIFS | TRACK_CHECK_VOLUME;
				break;
			case FILFILE_DEVICE_REDIRECTOR_WEBDAV:
				m_flags |= TRACK_WEBDAV | TRACK_CHECK_VOLUME;
				break;
			case FILFILE_DEVICE_REDIRECTOR_NETWARE:
				m_flags |= TRACK_NETWARE | TRACK_CHECK_VOLUME;
				break;
			default:
				ASSERT(false);
				break;
		}

		return STATUS_UNSUCCESSFUL;
	}

	if(m_flags & TRACK_CHECK_VOLUME)
	{
		ASSERT(m_volume);
		ASSERT(m_volumeLength);

		len = m_volumeLength / sizeof(WCHAR);

		if(!m_directory)
		{
			// [\Server\Share\Dir\file.typ]
			// [\;Y:00000abc\Server\Share\Dir\file.typ]

			// Look for session component
			if(m_volume[1] == L';')
			{
				while(++index < len)
				{
					if(m_volume[index] == L'\\')
					{
						break;
					}
				}

				len = (m_volumeLength / sizeof(WCHAR)) - index;

				RtlMoveMemory(m_volume, m_volume + index, len * sizeof(WCHAR));

				RtlZeroMemory(m_volume + len, index * sizeof(WCHAR));

				index = 0;
			}

			// Search for start of directory component by skipping server and share component
			while(++index < len)
			{
				if(m_volume[index] == L'\\')
				{
					break;
				}
			}
			
			while(++index < len)
			{
				if(m_volume[index] == L'\\')
				{
					break;
				}
			}

			m_volumeLength = (USHORT) (index * sizeof(WCHAR));

			m_directory		  = m_volume + index;
			m_directoryLength = sizeof(WCHAR);

			if(len > index)
			{
				m_directoryLength = (USHORT) ((len - index) * sizeof(WCHAR));
			}
		}

		len = m_volumeLength / sizeof(WCHAR);

		ASSERT(m_directory);
		ASSERT(m_directoryLength);
	
		ASSERT(!m_file);
		ASSERT(!m_fileLength);

		// Estimate server's length
		LONG serverLen = 1;

		while(++serverLen < len)
		{
			if(m_volume[serverLen] == L'\\')
			{
				break;
			}
		}

		ASSERT(serverLen < len);

		if(CFilterControl::IsWindowsVistaOrLater())
		{
			// Vista WebDAV UNC syntax? [\SERVER\DavWWWRoot\dir\...]
			if(!_wcsnicmp(m_volume + serverLen, L"\\DavWWWRoot\\", 12))
			{
				m_flags	&= ~TRACK_CIFS;
				m_flags |=  TRACK_WEBDAV;
			}
		}

		if(m_flags & TRACK_CIFS)
		{
			// Look for DFS's weird root syntax:
			if(m_directoryLength >= m_volumeLength)
			{
				// Simple style? [\SERVER\share\server\share]
				if(!_wcsnicmp(m_volume, m_directory, len))
				{
					USHORT const delta = m_directoryLength - m_volumeLength;

					if(delta)
					{
						RtlMoveMemory(m_directory, 
									  (UCHAR*) m_directory + m_volumeLength, 
									  delta);

						RtlZeroMemory((UCHAR*) m_directory + delta, 
									  m_directoryLength - delta);

						m_directoryLength = delta;
					}
					else
					{
						RtlZeroMemory(m_directory + 1, m_directoryLength);

						m_directoryLength = sizeof(WCHAR);
					}
				}
				else
				{
					// FQDN style? [\SERVER\share\server.domain.dom\share]. Compare server components
					if(!_wcsnicmp(m_volume, m_directory, serverLen))
					{
						index = 0;

						len = m_directoryLength / sizeof(WCHAR);

						while(++index < len)
						{
							if(m_directory[index] == L'\\')
							{
								break;
							}
						}

						ASSERT(index <= len);

						// Compare share components
						if(!_wcsnicmp(m_volume + serverLen,
									  m_directory + index,
									  (m_volumeLength / sizeof(WCHAR)) - serverLen))
						{
							RtlMoveMemory(m_volume, 
										  m_directory, 
										  m_directoryLength);

							RtlZeroMemory((UCHAR*) m_volume + m_directoryLength, 
										  m_volumeLength);

							len = index + (m_volumeLength / sizeof(WCHAR)) - serverLen;

							m_volumeLength = (USHORT)(len * sizeof(WCHAR));

							m_directory = m_volume + len;

							ASSERT(m_directoryLength >= m_volumeLength);
							
							m_directoryLength -= m_volumeLength;

							// Root directory?
							if(!m_directoryLength)
							{
								m_directoryLength = sizeof(WCHAR);

								m_directory[0] = L'\\';
							}
						}
					}
				}
			}
		}
	}

	len = m_directoryLength / sizeof(WCHAR);

	// Not root directory?
	if(len > 1)
	{
		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		len--;

		// Is file name given?
		if(m_directory[len] != L'\\')
		{
			m_deepness = 0;

			if(pathFlags & PATH_DEEPNESS)
			{
				m_flags |= TRACK_TYPE_FILE;
			}

			// Is directory type at all?
			if(m_directory[0] != L'\\')
			{
				m_file		 = m_directory;
				m_fileLength = m_directoryLength;

				m_directory		  = 0;
				m_directoryLength = 0;
			}
			else
			{
				while(len > 0)
				{
					if(m_directory[len] == L'\\')
					{
						break;
					}
					else if(m_directory[len] == L':')
					{
						// Streams are only valid for files
						m_flags |= TRACK_ALTERNATE_STREAM | TRACK_TYPE_FILE;
					}

					len--;
				};

				// External type hint or ADS?
				if(m_flags & TRACK_TYPE_FILE)
				{
					m_file	     = m_directory + len + 1;
					m_fileLength = m_directoryLength - (USHORT) ((len + 1) * sizeof(WCHAR));

					m_directoryLength = sizeof(WCHAR);

					if(len)
					{
						m_directoryLength = (USHORT) (len * sizeof(WCHAR));
					}
				}
			}
		}
	}

	if(m_file)
	{
		m_flags &= ~TRACK_TYPE_DIRECTORY;
		m_flags |=  TRACK_TYPE_FILE;

		len = m_fileLength / sizeof(WCHAR);

		// Look for ADS and short component in file name
		while(len >= 0)
		{
			if(m_file[len] == L'\\')
			{
				// Not NTFS stream syntax?
				if(m_file[len + 1] != L':')
				{
					// Adjust lenght
					len++;
						
					m_fileLength -= (USHORT) (len * sizeof(WCHAR));

					RtlMoveMemory(m_file, m_file + len, m_fileLength);
					RtlZeroMemory((UCHAR*) m_file + m_fileLength, len * sizeof(WCHAR));

					break;
				}
			}
			else if(m_file[len] == L'~')
			{
				// Skip tilda if it is very first char. Used by Word for intermediate files
				if(len)
				{
					m_flags |= TRACK_SHORT_COMPONENT;
				}
			}
			else if(m_file[len] == L':')
			{
				m_flags |= TRACK_ALTERNATE_STREAM;
			}

			len--;
		};

		if(m_flags & TRACK_ALTERNATE_STREAM)
		{
			ASSERT(m_file);
			ASSERT(m_fileLength);

			// NTFS alternate stream syntax:
			//
			// 1. [Dir\file.typ::$Data] - default
			// 2. [Dir\file.typ:streamName:$Data]
			// 3. [Dir\file.typ\:streamName:$Data] or Vista: [Dir\file.typ\:streamName]
						
			if((m_file[0] == L':') && m_directory)
			{
				ASSERT(m_directoryLength);

				// Take last directrory component as filename
				len = (m_directoryLength / sizeof(WCHAR)) - 1;

				while(len)
				{
					if(m_directory[len] == L'\\')
					{
						break;
					}

					len--;
				};

				if(len > 1)
				{
					len++;

					m_file		 = m_directory + len;
					m_fileLength = (USHORT)(m_directoryLength - (len * sizeof(WCHAR)));

					ASSERT(m_directoryLength >= m_fileLength);
					m_directoryLength -= m_fileLength + sizeof(WCHAR);
				}
			}
			else
			{
				len = m_fileLength / sizeof(WCHAR);

				// Estimate file length without NTFS stream components
				for(index = 0; index < len; ++index)
				{
					if(m_file[index] == L':')
					{
						break;
					}
					else if((m_file[index] == L'\\') && (m_file[index + 1] == L':'))
					{
						break;
					}
				}

				ASSERT(index);

				if(index < len)
				{
					// Just strip off stream components
					m_fileLength = (USHORT) (index * sizeof(WCHAR));
				}
			}
		}
	}
	else
	{
		m_flags &= ~TRACK_TYPE_FILE;
		m_flags |=  TRACK_TYPE_DIRECTORY;

		len = m_directoryLength / sizeof(WCHAR);

		// Skip root directory
		if(len > 1)
		{
			if(m_directory[len - 1] == L'\\')
			{
				// Do not count very last backslash
				m_directoryLength -= sizeof(WCHAR);

				len--;
			}
			else if(m_directory[len] != L'\\') 
			{
				// Ensure trailing backslash				
				m_directory[len]	 = L'\\';
				m_directory[len + 1] = UNICODE_NULL;
			}
		}

		// Compute given depth difference (deepness), if we should do so
		if(pathFlags & PATH_DEEPNESS)
		{
			m_deepness = ~0u;

			while(--len)
			{
				if(m_directory[len] != L'\\')
				{
					break;
				}

				m_deepness++;
			};

			if(m_deepness != ~0u)
			{
				m_directoryLength -= ((USHORT) m_deepness + 1) * sizeof(WCHAR);

				UCHAR *start = (UCHAR*) m_directory + m_directoryLength;

				// Not root directory?
				if(m_directoryLength > sizeof(WCHAR))
				{
					start += sizeof(WCHAR);
				}
				
				RtlZeroMemory(start, (m_deepness + 1) * sizeof(WCHAR));
			}
		}
	}

	m_directoryDepth = 0;

	len = m_directoryLength / sizeof(WCHAR);
	
	// Still not root directory?
	if(len > 1)
	{
		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		// Post processing for any type
		for(index = 0; index < len; ++index)
		{
			if(m_directory[index] == L'\\')
			{
				m_directoryDepth++;
			}
			else if(m_directory[index] == L'~')
			{
				// Skip tilda if it is very first char. Used by Word for intermediate files
				if(index && (m_directory[index - 1] != L'\\'))
				{
					m_flags |= TRACK_SHORT_COMPONENT;
				}
			}
		}
	}

	ASSERT(m_flags  & (TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY));
	ASSERT((m_flags & (TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY)) != (TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterPath::Close()
{
	if(m_volume)
	{
		ExFreePool(m_volume);
	}
	else if(m_directory)
	{
		ExFreePool(m_directory);
	}
	else if(m_file)
	{
		ExFreePool(m_file);
	}

	RtlZeroMemory(this, sizeof(*this));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::Swap(CFilterPath *path, bool takeOver)
{
	ASSERT(path);

	PAGED_CODE();

	if(takeOver)
	{
		// Transfer ownership
		*this = *path;
		// Clear source
		RtlZeroMemory(path, sizeof(CFilterPath));
	}
	else
	{
		// Exchange
		CFilterPath temp(*path);
		*path = *this;
		*this = temp;
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

UNICODE_STRING* CFilterPath::UnicodeString(UNICODE_STRING *ustr) const
{
	ASSERT(ustr);

	PAGED_CODE();

	ASSERT(m_volume || m_directory || m_file);

	ustr->Buffer = 0;
	ustr->Length = 0;

	if(m_volume)
	{
		ustr->Buffer = m_volume;

		ustr->Length = m_volumeLength;
	}

	if(m_directory)
	{
		if(!ustr->Buffer)
		{
			ustr->Buffer = m_directory;
		}

		ustr->Length += m_directoryLength;
	}

	if(m_file)
	{
		if(!ustr->Buffer)
		{
			ustr->Buffer = m_file;
		}

		// Add path separator?
		if(m_directory)
		{
			ustr->Length += sizeof(WCHAR);
		}

		ustr->Length += m_fileLength;
	}

	// Add terminating NULL
	ustr->MaximumLength = ustr->Length + sizeof(WCHAR);

	return ustr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterPath::GetLength(ULONG flags) const
{
	PAGED_CODE();

	// Compute needed buffer size in bytes arcording to flags value
	ULONG len = m_directoryLength;

	if(flags & PATH_VOLUME)
	{
		len += m_volumeLength;
	}

	if(flags & PATH_PREFIX)
	{
		if(m_flags & (TRACK_CIFS | TRACK_WEBDAV))
		{
			len += 24 * sizeof(WCHAR);
		}
		else if(m_flags & TRACK_NETWARE)
		{
			len += 25 * sizeof(WCHAR);
		}
	}

	if(flags & PATH_FILE)
	{
		len += m_fileLength;
	}
	else if(flags & PATH_AUTOCONFIG)
	{
		len += g_filFileAutoConfigNameLength * sizeof(WCHAR);
	}

	if(flags & PATH_DEEPNESS)
	{
		if(m_directory)
		{
			if(m_deepness != ~0u)
			{
				ASSERT(m_deepness < 256);

				UCHAR const deepness = (UCHAR) m_deepness;

				len += deepness * sizeof(WCHAR);
			}

			len += (1 + 4) * sizeof(WCHAR);
		}
	}

	// Always add space for separator and terminator
	len += 2 * sizeof(WCHAR);

	return len;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

LPWSTR CFilterPath::CopyTo(ULONG flags, ULONG *length) const
{
	PAGED_CODE();

	ULONG pathLength = GetLength(flags);

	LPWSTR path	= (LPWSTR) ExAllocatePool(PagedPool, pathLength);

	if(path)
	{
		RtlZeroMemory(path, pathLength);
			
		pathLength = Write(path, pathLength, flags);

		if(pathLength)
		{
			if(length)
			{
				*length = pathLength;
			}

			return path;
		}

		ExFreePool(path);
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::CopyFrom(CFilterPath const* that, ULONG flags)
{
	ASSERT(that);

	PAGED_CODE();

	// Should be fresh
	ASSERT(!m_volume);
	ASSERT(!m_directory);
	ASSERT(!m_file);
    
	// Must be valid
	ASSERT(that->m_volume);
	ASSERT(that->m_volumeLength);
	ASSERT(that->m_directory);
	ASSERT(that->m_directoryLength);

	// Binary copy
	*this = *that;

	ULONG const len = m_volumeLength + m_directoryLength + m_fileLength + (2 * sizeof(WCHAR));

	m_volume = (LPWSTR) ExAllocatePool(PagedPool, len);

	if(!m_volume)
	{
		RtlZeroMemory(this, sizeof(*this));

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(m_volume, len);
	RtlCopyMemory(m_volume, that->m_volume, len - sizeof(WCHAR));

	m_directory	= m_volume + (m_volumeLength / sizeof(WCHAR));
			
	if((flags & PATH_DIRECTORY) && m_directoryDepth)
	{
		ASSERT(m_directoryLength > sizeof(WCHAR));

		ULONG curr = m_directoryLength / sizeof(WCHAR);

		// Get rid of last directory component, if any
		while(--curr)
		{
			if(m_directory[curr] == L'\\')
			{
				RtlZeroMemory(m_directory + curr + 1, m_directoryLength - (curr * sizeof(WCHAR)));

				m_directoryLength = (USHORT) (curr * sizeof(WCHAR));
				m_directoryDepth--;

				m_file		  = 0;
				m_fileLength  = 0;
				break;
			}
		}
	}
	else if(m_file)
	{
		ASSERT(m_fileLength);

		// Assume root
		m_file = m_directory + (m_directoryLength / sizeof(WCHAR));

		if(m_directoryLength > sizeof(WCHAR))
		{
			// Skip separator
			m_file++;
		}
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterPath::Write(LPWSTR buffer, ULONG bufferLength, ULONG flags) const
{
	ASSERT(buffer);
	ASSERT(bufferLength);

	PAGED_CODE();

	// Check for incompatible flags
	ASSERT((flags & (PATH_FILE | PATH_DIRECTORY))  != (PATH_FILE | PATH_DIRECTORY));
	ASSERT((flags & (PATH_FILE | PATH_AUTOCONFIG)) != (PATH_FILE | PATH_AUTOCONFIG));

	// Check provided buffer size
	if(GetLength(flags) > bufferLength)
	{
		return 0;
	}

	ULONG curr = 0;

	// Add Volume name?
	if((flags & PATH_VOLUME) && m_volume)
	{
		ASSERT(m_volumeLength);

		// Add redirector prefix?
		if(flags & PATH_PREFIX)
		{
			if(m_flags & TRACK_CIFS)
			{
				// Change it dynamically?
				if((flags & PATH_DYNAMIC) && CFilterControl::IsWindowsVistaOrLater())
				{
					RtlCopyMemory(buffer, L"\\Device\\Mup", 11 * sizeof(WCHAR));
					curr = 11;
				}
				else
				{
					RtlCopyMemory(buffer, L"\\Device\\LanmanRedirector", 24 * sizeof(WCHAR));
					curr = 24;
				}
			}
			else if(m_flags & TRACK_WEBDAV)
			{
				// Change it dynamically?
				if((flags & PATH_DYNAMIC) && CFilterControl::IsWindowsVistaOrLater())
				{
					RtlCopyMemory(buffer, L"\\Device\\Mup", 11 * sizeof(WCHAR));
					curr = 11;
				}
				else
				{
					RtlCopyMemory(buffer, L"\\Device\\WebDavRedirector", 24 * sizeof(WCHAR));
					curr = 24;
				}
			}
			else if(m_flags & TRACK_NETWARE)
			{
				RtlCopyMemory(buffer, L"\\Device\\NetWareRedirector", 25 * sizeof(WCHAR));
				curr = 25;
			}
		}

		RtlCopyMemory(buffer + curr, m_volume, m_volumeLength);

		curr += m_volumeLength / sizeof(WCHAR);
	}

	if(m_directory)
	{
		ASSERT(m_directoryLength);

		RtlCopyMemory(buffer + curr, m_directory, m_directoryLength);

		curr += m_directoryLength / sizeof(WCHAR);

		if((flags & PATH_DIRECTORY) && m_directoryDepth)
		{
			// Get rid of last directory component, if any
			while(--curr)
			{
				if(buffer[curr] == L'\\')
				{
					break;
				}
			}

			curr++;
		}
	}

	if(flags & PATH_FILE)
	{
		if(m_file)
		{
			ASSERT(m_fileLength);

			if(curr && (buffer[curr - 1] != L'\\'))
			{
				buffer[curr] = L'\\';
				curr++;
			}

			RtlCopyMemory(buffer + curr, m_file, m_fileLength);

			curr += m_fileLength / sizeof(WCHAR);

			flags &= ~PATH_DEEPNESS;
		}
	}
	else if(flags & PATH_AUTOCONFIG)
	{			
		if(curr && (buffer[curr - 1] != L'\\'))
		{
			buffer[curr] = L'\\';
			curr++;
		}

		RtlCopyMemory(buffer + curr, 
					  g_filFileAutoConfigName, 
					  g_filFileAutoConfigNameLength * sizeof(WCHAR));

		curr += g_filFileAutoConfigNameLength;

		flags &= ~PATH_DEEPNESS;
	}

	if(flags & PATH_DEEPNESS)
	{
		if(m_directory)
		{
			ASSERT(m_directoryLength);

			// Skip root directory
			if(m_directoryLength != sizeof(WCHAR))
			{
				buffer[curr] = L'\\';
				curr++;
			}

			// Infinite deepness?
			if(m_deepness != ~0u)
			{
				ASSERT(m_deepness <= 256);

				// Append depth difference, max deepness is 256
				UCHAR diff = (UCHAR) m_deepness;

				do
				{
					buffer[curr] = L'\\';
					curr++;
				}
				while(diff--);
			}
		}
	}

	// Terminate
	buffer[curr] = UNICODE_NULL;
	curr++;

	return curr * sizeof(WCHAR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::GetAutoConfig(UNICODE_STRING *autoConfig, ULONG flags) const
{
	ASSERT(autoConfig);

	PAGED_CODE();

	flags |= PATH_AUTOCONFIG;

	if(m_flags & TRACK_CHECK_VOLUME)
	{
		flags |= PATH_VOLUME;
	}

	ULONG const bufferSize = GetLength(flags);

	LPWSTR buffer = (LPWSTR) ExAllocatePool(PagedPool, bufferSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Build full path
	ULONG const written = Write(buffer, bufferSize, flags);

	if(!written)
	{
		ExFreePool(buffer);

		return STATUS_UNSUCCESSFUL;
	}

	if(bufferSize > written)
	{
		RtlZeroMemory((UCHAR*) buffer + written, bufferSize - written);
	}

	autoConfig->Length		  = (USHORT) written - sizeof(WCHAR);
	autoConfig->MaximumLength = (USHORT) written;
	autoConfig->Buffer		  = buffer;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterPath::SetType(ULONG type)
{
	PAGED_CODE();

	// Support other flags as well
	if(PATH_DIRECTORY == type)
	{
		type = TRACK_TYPE_DIRECTORY;
	}
	else if(PATH_FILE == type)
	{
		type = TRACK_TYPE_FILE;
	}

	// Already of right type?
	if(type == (m_flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE)))
	{
		return STATUS_SUCCESS;
	}

	if(type == TRACK_TYPE_FILE)
	{
		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		if(!m_file && !m_fileLength)
		{
			ASSERT(!m_file);
			ASSERT(!m_fileLength);

			LONG len = m_directoryLength / sizeof(WCHAR);

			// Remove trailing backslash, if any
			if(m_directory[len] == L'\\')
			{
				m_directory[len] = UNICODE_NULL;
			}

			while(--len >= 0)
			{
				if(m_directory[len] == L'\\')
				{
					break;
				}
			};

			if(len >= 0)
			{
				m_file		 = m_directory + len + 1;
				m_fileLength = m_directoryLength - (USHORT) ((len + 1) * sizeof(WCHAR));

				// Assume root
				m_directoryLength = sizeof(WCHAR);

				if(len)
				{
					m_directoryLength = (USHORT)((m_file - m_directory - 1) * sizeof(WCHAR));	
				}

				m_directoryDepth--;
			}
		}

		m_flags &= ~TRACK_TYPE_DIRECTORY;
		m_flags |=  TRACK_TYPE_FILE;
	}
	else
	{
		ASSERT(type == TRACK_TYPE_DIRECTORY);

		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		if(m_file && m_fileLength)
		{
			// Not root directory ?
			if(m_directoryLength > sizeof(WCHAR))
			{
				m_fileLength += sizeof(WCHAR);
			}

			m_directoryLength += m_fileLength;
			m_directoryDepth  += 1;

			m_file		 = 0;
			m_fileLength = 0;
		}

		if(m_directoryLength > sizeof(WCHAR))
		{
			// Do not count last backslash
			if(m_directory[(m_directoryLength / sizeof(WCHAR)) - 1] == L'\\')
			{
				m_directoryLength -= sizeof(WCHAR);

				ASSERT(m_directoryDepth);
				m_directoryDepth  -= 1;
			}
			else if(m_directory[m_directoryLength / sizeof(WCHAR)] != L'\\') 
			{
				// Ensure trailing backslash				
				m_directory[m_directoryLength / sizeof(WCHAR)]		 = L'\\';
				m_directory[(m_directoryLength / sizeof(WCHAR)) + 1] = UNICODE_NULL;
			}
		}

		m_flags &= ~TRACK_TYPE_FILE;
		m_flags |=  TRACK_TYPE_DIRECTORY;
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterPath::Hash(ULONG flags) const
{
	ASSERT(flags);

	PAGED_CODE();

	if(flags & PATH_FILE)
	{
		ASSERT(m_file);
		ASSERT(m_fileLength);

		return CFilterBase::Hash(m_file, m_fileLength);		
	}
	else if(flags & PATH_DIRECTORY)
	{
		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		if( !(flags & PATH_TAIL))
		{
			// Hash whole directory path
			return CFilterBase::Hash(m_directory, m_directoryLength);
		}

		// Hash last directory component only

		// Root directory?
		if(!m_directoryDepth)
		{
			ASSERT(m_directoryLength == sizeof(WCHAR));

			// Hash of single backslash is const
			return L'\\';
		}

		ASSERT(m_directoryLength > sizeof(WCHAR));

		ULONG start = 0;

		// More than one directory component?
		if(m_directoryDepth > 1)
		{
			// Separate last one
			start = m_directoryLength / sizeof(WCHAR);

			while(--start)
			{
				if(m_directory[start] == L'\\')
				{
					break;
				}
			}
		}

		ASSERT(m_directoryLength > start * sizeof(WCHAR));
		return CFilterBase::Hash(m_directory + start, m_directoryLength - (start * sizeof(WCHAR)));
	}
	else if(flags & PATH_VOLUME)
	{
		ASSERT(m_volume);
		ASSERT(m_volumeLength);

		return CFilterBase::Hash(m_volume, m_volumeLength);	
	}

	// We should never come here
	ASSERT(false);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterPath::Match(CFilterPath const* candidate, bool exact) const
{
	ASSERT(candidate);

	PAGED_CODE();

	LPWSTR currentDir			= m_directory;
	LPWSTR candidateDir			= candidate->m_directory;

	USHORT candidateDirLength	= candidate->m_directoryLength;
	USHORT currentDirLength		= m_directoryLength;
	
	// Involve Volume names in compares?
	if(m_flags & TRACK_CHECK_VOLUME)
	{
		ASSERT(candidate->m_flags & TRACK_CHECK_VOLUME);

		currentDir		    = m_volume;
		currentDirLength   += m_volumeLength;

		candidateDir	    = candidate->m_volume;
		candidateDirLength += candidate->m_volumeLength;
	}
	else
	{
		ASSERT( !(candidate->m_flags & TRACK_CHECK_VOLUME));
	}

	// Exact path match or simple file match?
	if(exact || m_file)
	{
		ASSERT(!m_file || m_fileLength);
		ASSERT(!candidate->m_file || candidate->m_fileLength);

		if(currentDirLength == candidateDirLength)
		{
			if(m_directoryDepth == candidate->m_directoryDepth)
			{
				if(m_fileLength == candidate->m_fileLength)
				{
					USHORT length = candidateDirLength; 

					// Path?
					if(length)
					{
						if(candidate->m_file)
						{
							// Not root directory?
							if(length > sizeof(WCHAR))
							{
								// Add separator
								length += sizeof(WCHAR);
							}

							length += candidate->m_fileLength;
						}

						ASSERT(currentDir);
						ASSERT(candidateDir);

						if(!_wcsnicmp(currentDir, candidateDir, length / sizeof(WCHAR)))
						{
							const_cast<CFilterPath*>(candidate)->m_flags |= TRACK_MATCH_EXACT;

							return true;
						}
					}
					else
					{
						// Single file:
						ASSERT(m_file);
						ASSERT(candidate->m_file);

						if(!_wcsnicmp(m_file, candidate->m_file, m_fileLength / sizeof(WCHAR)))
						{
							const_cast<CFilterPath*>(candidate)->m_flags |= TRACK_MATCH_EXACT;

							return true;
						}
					}
				}
			}
		}
	}
	else
	{
		ASSERT(!m_file);

		// Is sub-match possible at all?
		if(m_directoryDepth < candidate->m_directoryDepth)
		{
			// Always match on root directory, if such
			if(currentDirLength == sizeof(WCHAR))
			{
				return true;
			}

			USHORT length = currentDirLength / sizeof(WCHAR);

			if(m_directoryLength > sizeof(WCHAR))
			{
				// Take path separator (or terminator) into account
				length++;
			}

			// Check for a sub-match
			if(!_wcsnicmp(currentDir, candidateDir, length))
			{
				// Check deepness
				if(candidate->m_directoryDepth - m_directoryDepth <= (USHORT) m_deepness)
				{
					return true;					
				}
			}
		}
		else if(m_directoryDepth == candidate->m_directoryDepth)
		{
			if(candidateDirLength == currentDirLength)
			{
				// Check for a match
				if(!_wcsnicmp(currentDir, candidateDir, currentDirLength / sizeof(WCHAR)))
				{
					if(!candidate->m_file)
					{
						const_cast<CFilterPath*>(candidate)->m_flags |= TRACK_MATCH_EXACT;
					}

					return true;
				}
			}
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterPath::MatchSpecial(CFilterPath const* candidate) const
{
	ASSERT(candidate);
	
	PAGED_CODE();

	if(m_flags & TRACK_WILDCARD)
	{
		ASSERT(!m_volume);
		ASSERT(!m_directory);
		ASSERT(m_file);

		if(candidate->m_file)
		{
			// Perform wildcard match
			UNICODE_STRING candidateUstr;

			candidateUstr.Length		= candidate->m_fileLength;
			candidateUstr.MaximumLength = candidate->m_fileLength + sizeof(WCHAR);
			candidateUstr.Buffer		= candidate->m_file;

			UNICODE_STRING currentUstr;
			UnicodeString(&currentUstr);

			// Use system function for wildcard match
			if(FsRtlIsNameInExpression(&currentUstr, &candidateUstr, true, 0))
			{
				// Matched
				return true;
			}
		}

		return false;
	}

	// Match against Volume part, if any
	if(m_volume)
	{
		ASSERT(m_volumeLength);

		if(candidate->m_volume)
		{
			ASSERT(candidate->m_volumeLength);

			if(m_volumeLength != candidate->m_volumeLength)
			{
				return false;
			}

			if(_wcsnicmp(m_volume, candidate->m_volume, candidate->m_volumeLength / sizeof(WCHAR)))
			{
				return false;
			}
		}
	}

	// Match against Directory part, if any
	if(m_directory)
	{
		ASSERT(m_directoryLength);
		ASSERT(candidate->m_directory);
		ASSERT(candidate->m_directoryLength);

		// Is sub-match possible at all?
		if(m_directoryDepth > candidate->m_directoryDepth)
		{
			return false;
		}
		else if(m_directoryDepth == candidate->m_directoryDepth)
		{
			if(m_directoryLength != candidate->m_directoryLength)
			{
				return false;
			}
		}

		// Skip out root directory
		if(m_directoryLength != sizeof(WCHAR))
		{
			USHORT length = m_directoryLength / sizeof(WCHAR);

			if(length > 1)
			{
				// Take path separator (or terminator) into account
				length++;
			}

			// Check for sub-matches
			if(_wcsnicmp(m_directory, candidate->m_directory, length))
			{
				return false;
			}
		}
	}

	// Match against File part, if any
	if(m_file)
	{
		ASSERT(m_fileLength);

		if(!candidate->m_file)
		{
			return false;
		}

		ASSERT(candidate->m_fileLength);
				
		if(candidate->m_fileLength != m_fileLength)
		{
			return false;
		}

		// Check for a file match
		if(_wcsnicmp(candidate->m_file, m_file, m_fileLength / sizeof(WCHAR)))
		{
			return false;
		}
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if DBG

#pragma PAGEDCODE

void CFilterPath::Print(ULONG flags)
{
	LPWSTR path = CopyTo(flags);

	if(path)
	{
		DbgPrint("%ws", path);

		ExFreePool(path);
	}
}

#endif // DBG
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
