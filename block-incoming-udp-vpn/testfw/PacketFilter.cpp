/******************************************************************************
  PacketFilter.cpp - PacketFilter class implemenation.
 
                                                 Mahesh S
                                                 swatkat_thinkdigit@yahoo.co.in
                                                 http://swatrant.blogspot.com/


******************************************************************************/
#include "stdafx.h"
#include "PacketFilter.h"
#include "openvpn-plugin.h"
#include <iphlpapi.h>
#include <time.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "Ws2_32.lib")
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


/******************************************************************************
PacketFilter::PacketFilter() - Constructor
*******************************************************************************/
PacketFilter::PacketFilter()
{
    try
    {
        // Initialize member variables.
        m_hEngineHandle = NULL;
        ::ZeroMemory( &m_subLayerGUID, sizeof( GUID ) );
    }
    catch(...)
    {
    }
}

/******************************************************************************
PacketFilter::~PacketFilter() - Destructor
*******************************************************************************/
PacketFilter::~PacketFilter()
{
    try
    {
        // Stop firewall before closing.
        StopFirewall();
    }
    catch(...)
    {
    }
}

/******************************************************************************
PacketFilter::CreateDeleteInterface - This method creates or deletes a packet
                                      filter interface.
*******************************************************************************/
DWORD PacketFilter::CreateDeleteInterface( bool bCreate )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if( bCreate )
        {
			FWPM_SESSION0 session = {0};
			session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            // Create packet filter interface.
            dwFwAPiRetCode =  ::FwpmEngineOpen0( NULL,
                                                 RPC_C_AUTHN_WINNT,
                                                 NULL,
                                                 &session,
                                                 &m_hEngineHandle );
        }
        else
        {
            if( NULL != m_hEngineHandle )
            {
                // Close packet filter interface.
                dwFwAPiRetCode = ::FwpmEngineClose0( m_hEngineHandle );
                m_hEngineHandle = NULL;
            }
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::BindUnbindInterface - This method binds to or unbinds from a
                                    packet filter interface.
*******************************************************************************/
DWORD PacketFilter::BindUnbindInterface( bool bBind )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
    try
    {
        if( bBind )
        {
            RPC_STATUS rpcStatus = {0};
            FWPM_SUBLAYER0 SubLayer = {0};

            // Create a GUID for our packet filter layer.
            rpcStatus = ::UuidCreate( &SubLayer.subLayerKey );
            if( NO_ERROR == rpcStatus )
            {
                // Save GUID.
                ::CopyMemory( &m_subLayerGUID,
                              &SubLayer.subLayerKey,
                              sizeof( SubLayer.subLayerKey ) );

                // Populate packet filter layer information.
                SubLayer.displayData.name = FIREWALL_SUBLAYER_NAMEW;
                SubLayer.displayData.description = FIREWALL_SUBLAYER_NAMEW;
                SubLayer.flags = 0;
                SubLayer.weight = 0x100;

                // Add packet filter to our interface.
                dwFwAPiRetCode = ::FwpmSubLayerAdd0( m_hEngineHandle,
                                                     &SubLayer,
                                                     NULL );
            }
        }
        else
        {
            // Delete packet filter layer from our interface.
            dwFwAPiRetCode = ::FwpmSubLayerDeleteByKey0( m_hEngineHandle,
                                                         &m_subLayerGUID );
            ::ZeroMemory( &m_subLayerGUID, sizeof( GUID ) );
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}

/******************************************************************************
PacketFilter::AddRemoveFilter - This method adds or removes a filter to an
                                existing interface.
*******************************************************************************/
DWORD PacketFilter::AddRemoveFilter( bool bAdd )
{
    DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	UINT64 filterid;
	FWP_V4_ADDR_AND_MASK addrandmask4;
	FWP_V6_ADDR_AND_MASK addrandprefix6;
    try
    {
        if( bAdd )
        {
                        FWPM_FILTER0 Filter = {0};
                        FWPM_FILTER_CONDITION0 Condition[3] = {0};

                        // Prepare filter.
                        Filter.subLayerKey = m_subLayerGUID;
                        Filter.displayData.name = FIREWALL_SERVICE_NAMEW;
                        Filter.weight.type = FWP_EMPTY;
                        Filter.filterCondition = Condition;
						Filter.numFilterConditions = 3;

						// PERMIT on IPv4 accept layer
						Filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
						Filter.action.type = FWP_ACTION_PERMIT;

                        // First condition. Match UDP protocol.
                        Condition[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                        Condition[0].matchType = FWP_MATCH_EQUAL;
                        Condition[0].conditionValue.type = FWP_UINT8;
                        Condition[0].conditionValue.uint8 = IPPROTO_UDP;

						// Second condition. Match only unicast addresses.
						Condition[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE;
						Condition[1].matchType = FWP_MATCH_EQUAL;
						Condition[1].conditionValue.type = FWP_UINT8;
						Condition[1].conditionValue.uint8 = NlatUnicast;

						// Third condition. Match remote IP addresses if they come
						// from a LAN segment (e.g. 192.168.0.0 255.255.255.0 and others
						// for IPv4, fd00::/8, fe80::/10 for IPv6).
						// Incoming LAN packets should be permitted because
						// replies to said packets go via LAN, not VPN.
						Condition[2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
						Condition[2].matchType = FWP_MATCH_EQUAL;
						Condition[2].conditionValue.type = FWP_V4_ADDR_MASK;
						Condition[2].conditionValue.v4AddrMask = &addrandmask4;

						for (std::vector<ADDRMASK4>::iterator adapter = adapteripandmask4.begin();
						adapter != adapteripandmask4.end(); ++adapter) {
							ADDRMASK4 adapter64 = *adapter;
							addrandmask4.addr = adapter64.addr;
							addrandmask4.mask = adapter64.mask;

							dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
								&Filter,
								NULL,
								&filterid);
							printf("Filter (Permit local IPv4 addresses) added with ID=%I64d\r\n", filterid);
							filterids.push_back(filterid);
						}

						Filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
						Condition[2].conditionValue.type = FWP_V6_ADDR_MASK;
						Condition[2].conditionValue.v6AddrMask = &addrandprefix6;

						for (std::vector<FWP_V6_ADDR_AND_MASK>::iterator adapter = adapteripandprefix6.begin();
						adapter != adapteripandprefix6.end(); ++adapter) {
							FWP_V6_ADDR_AND_MASK adapter64 = *adapter;
							std::copy(adapter64.addr, adapter64.addr + FWP_V6_ADDR_SIZE, addrandprefix6.addr);
							addrandprefix6.prefixLength = adapter64.prefixLength;

							dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
								&Filter,
								NULL,
								&filterid);
							printf("Filter (Permit local IPv6 addresses) added with ID=%I64d\r\n", filterid);
							filterids.push_back(filterid);
						}

						Filter.action.type = FWP_ACTION_BLOCK;

						// Third condition. Block everything (except already permitted by
						// the filters above) not from VPN TAP interface.
						Condition[2].fieldKey = FWPM_CONDITION_IP_ARRIVAL_INTERFACE;
						Condition[2].matchType = FWP_MATCH_NOT_EQUAL;
						Condition[2].conditionValue.type = FWP_UINT64;

							for (std::vector<uint64_t>::iterator tapluid = tapluids.begin();
							tapluid != tapluids.end(); ++tapluid) {
								uint64_t tapluid64 = *tapluid;
								Filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
								Condition[2].conditionValue.uint64 = &tapluid64;

								// Add filter condition to our interface. Save filter id in filterids.
								dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
									&Filter,
									NULL,
									&filterid);
								printf("Filter (Block IPv4 not from TAP interface) added with ID=%I64d\r\n", filterid);
								filterids.push_back(filterid);

								// Forth filter. Permit all IPv6 traffic from TAP.
								Filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

								// Add filter condition to our interface. Save filter id in filterids.
								dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
									&Filter,
									NULL,
									&filterid);
								printf("Filter (Block IPv6 not from TAP interface) added with ID=%I64d\r\n", filterid);
								filterids.push_back(filterid);
							}
							adapteripandmask4.clear();
							adapteripandprefix6.clear();
							tapluids.clear();
        }
        else
        {
			for (unsigned int i = 0; i < filterids.size(); i++) {
				dwFwAPiRetCode = ::FwpmFilterDeleteById0(m_hEngineHandle,
					filterids[i]);
			}
			filterids.clear();
        }
    }
    catch(...)
    {
    }
    return dwFwAPiRetCode;
}


/******************************************************************************
PacketFilter::StartFirewall - This public method starts firewall.
*******************************************************************************/
BOOL PacketFilter::StartFirewall()
{
    BOOL bStarted = FALSE;

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	ADDRMASK4 addrmask;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 2;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 3;
		}
	}

	// IPv4 related operations
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if ((strlen(pAdapter->IpAddressList.IpAddress.String) != 0) &&
				(strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0")))
			{
				// Found an active adapter with IP address
				addrmask.addr = IPv4(pAdapter->IpAddressList.IpAddress.String);
				addrmask.mask = IPv4(pAdapter->IpAddressList.IpMask.String);
				adapteripandmask4.push_back(addrmask);
			}
			pAdapter = pAdapter->Next;
		}
		// Push non-routable IPv4 addresses
		addrmask.addr = IPv4("10.0.0.0");
		addrmask.mask = IPv4("255.0.0.0");
		adapteripandmask4.push_back(addrmask);

		addrmask.addr = IPv4("172.16.0.0");
		addrmask.mask = IPv4("255.240.0.0");
		adapteripandmask4.push_back(addrmask);

		addrmask.addr = IPv4("192.168.0.0");
		addrmask.mask = IPv4("255.255.0.0");
		adapteripandmask4.push_back(addrmask);

		addrmask.addr = IPv4("169.254.0.0");
		addrmask.mask = IPv4("255.255.0.0");
		adapteripandmask4.push_back(addrmask);
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
		return 4;
	}
	if (pAdapterInfo)
		FREE(pAdapterInfo);


	// IPv6 and TAP adapters related operations
	/* Declare and initialize variables */

	DWORD dwSize = 0;
	dwRetVal = 0;
	FWP_V6_ADDR_AND_MASK addrprefix6;
	IN6_ADDR ipv6addr;

	unsigned int i = 0;

	// Set the flags to pass to GetAdaptersAddresses
	ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
		GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

	// default to unspecified address family (both)
	ULONG family = AF_INET6;

	LPVOID lpMsgBuf = NULL;

	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 0;
	ULONG Iterations = 0;

	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	IP_ADAPTER_PREFIX *pPrefix = NULL;

	// Allocate a 15 KB buffer to start with.
	outBufLen = 15000;

	do {
		pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);

		dwRetVal =
			GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			FREE(pAddresses);
			pAddresses = NULL;
		}
		else {
			break;
		}

		Iterations++;

	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < 3));

	if (dwRetVal == NO_ERROR) {
		// If successful, output some information from the data we received
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			if ((wcsstr(pCurrAddresses->Description, L"TAP-Windows Adapter V9") != NULL) ||
				(wcsstr(pCurrAddresses->Description, L"Viscosity Virtual Adapter") != NULL))
			{
				tapluids.push_back(pCurrAddresses->Luid.Value);
			}

			pPrefix = pCurrAddresses->FirstPrefix;
			for (
				IP_ADAPTER_PREFIX* prefix = pPrefix;
				NULL != prefix;
				prefix = prefix->Next)
			{
				ADDRESS_FAMILY family = prefix->Address.lpSockaddr->sa_family;
				if (family == AF_INET6)
				{
					// IPv6
					SOCKADDR_IN6* ipv6 = (SOCKADDR_IN6*)(prefix->Address.lpSockaddr);

					char str_buffer[INET6_ADDRSTRLEN] = { 0 };
					inet_ntop(AF_INET6, &(ipv6->sin6_addr), str_buffer, INET6_ADDRSTRLEN);

					std::string ipv6_str(str_buffer);
					//printf("%s/%u\n", ipv6_str.c_str(), prefix->PrefixLength);
					if ((ipv6_str.find("f") != 0) && (ipv6_str.find("::1") != 0))
					{
						std::copy(ipv6->sin6_addr.u.Byte, ipv6->sin6_addr.u.Byte + FWP_V6_ADDR_SIZE, addrprefix6.addr);
						addrprefix6.prefixLength = (uint8_t)prefix->PrefixLength;
						adapteripandprefix6.push_back(addrprefix6);
					}
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
		InetPton(AF_INET6, L"fd00::", &ipv6addr);
		std::copy(ipv6addr.u.Byte, ipv6addr.u.Byte + FWP_V6_ADDR_SIZE, addrprefix6.addr);
		addrprefix6.prefixLength = 8;
		adapteripandprefix6.push_back(addrprefix6);

		InetPton(AF_INET6, L"fe80::", &ipv6addr);
		std::copy(ipv6addr.u.Byte, ipv6addr.u.Byte + FWP_V6_ADDR_SIZE, addrprefix6.addr);
		addrprefix6.prefixLength = 10;
		adapteripandprefix6.push_back(addrprefix6);
	}
	else {
		printf("Call to GetAdaptersAddresses failed with error: %d\n",
			dwRetVal);
		if (pAddresses) {
			FREE(pAddresses);
		}
		return 5;
	}

	if (pAddresses) {
		FREE(pAddresses);
	}


	if (tapluids.size() <= 0) {
		printf("No TAP adapters found!\n");
		return 6;
	}

	printf("Found %zd TAP adapters\n", tapluids.size());

    try
    {
        // Create packet filter interface.
        if( ERROR_SUCCESS == CreateDeleteInterface( true ) )
        {
            // Bind to packet filter interface.
            if( ERROR_SUCCESS == BindUnbindInterface( true ) )
            {
                // Add filters.
                AddRemoveFilter( true );

                bStarted = TRUE;
            }
        }
    }
    catch(...)
    {
    }
    return bStarted;
}

/******************************************************************************
PacketFilter::StopFirewall - This method stops firewall.
*******************************************************************************/
BOOL PacketFilter::StopFirewall()
{
    BOOL bStopped = FALSE;
    try
    {
        // Remove all filters.
        AddRemoveFilter( false );

        // Unbind from packet filter interface.
        if( ERROR_SUCCESS == BindUnbindInterface( false ) )
        {
            // Delete packet filter interface.
            if( ERROR_SUCCESS == CreateDeleteInterface( false ) )
            {
                bStopped = TRUE;
            }
        }
    }
    catch(...)
    {
    }
    return bStopped;
}

void PrintTime()
{
	time_t rawtime;
	struct tm timeinfo;
	char str[26];
	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	asctime_s(str, sizeof str, &timeinfo);
	str[24] = '\0';
	printf("%s ", str);
}

uint32_t IPv4(const PCSTR input)
{
	IN_ADDR ipv4addr;
	InetPtonA(AF_INET, input, &ipv4addr);
	return ntohl(ipv4addr.S_un.S_addr);
}

#ifdef SAMPLE_APP
/******************************************************************************
main - Entry point.
*******************************************************************************/
int main()
{
    try
    {
        PacketFilter pktFilter;

        // Start firewall.
		
        if( pktFilter.StartFirewall() == TRUE )
        {
            printf( "\nFirewall started successfully...\n" );
        }
        else
        {
            printf( "\nError starting firewall. GetLastError() 0x%x", ::GetLastError() );
        }

        // Wait.
        printf( "\nPress any key to stop firewall...\n" );
        _getch();

        // Stop firewall.
        if( pktFilter.StopFirewall() )
        {
            printf( "\nFirewall stopped successfully...\n" );
        }
        else
        {
            printf( "\nError stopping firewall. GetLastError() 0x%x", ::GetLastError() );
        }

        // Quit.
        printf( "\nPress any key to exit...\n" );
        _getch();
    }
    catch(...)
    {
    }
}
#endif //SAMPLE_APP

#ifndef SAMPLE_APP
struct plugin_context {
	PacketFilter pktFilter;
};

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
	struct plugin_context *context;

	/*
	* Allocate our context
	*/
	context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));

	/*
	* We are only interested in intercepting the
	* UP and DOWN callbacks.
	*/
	*type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_ROUTE_UP) | OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN);

	return (openvpn_plugin_handle_t)context;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
	struct plugin_context *context = (struct plugin_context *) handle;
	free(context);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
	struct plugin_context *context = (struct plugin_context *) handle;

	if (type == OPENVPN_PLUGIN_ROUTE_UP) {
		PrintTime();
		printf("PLUGIN: Starting firewall\n");
		if (context->pktFilter.StartFirewall() == TRUE)
			return OPENVPN_PLUGIN_FUNC_SUCCESS;
		else {
			PrintTime();
			printf("PLUGIN: Start failed!\n");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}
	}
	if (type == OPENVPN_PLUGIN_DOWN) {
		PrintTime();
		printf("PLUGIN: Stopping firewall\n");
		if (context->pktFilter.StopFirewall() == TRUE)
				return OPENVPN_PLUGIN_FUNC_SUCCESS;
		else {
			PrintTime();
			printf("PLUGIN: Can't stop firewall!\n");
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}

	}
		PrintTime();
		printf("PLUGIN: Unknown handler!\n");
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
}
#endif //SAMPLE_APP