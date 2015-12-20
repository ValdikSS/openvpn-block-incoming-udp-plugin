/******************************************************************************
  PacketFilter.h  - PacketFilter class declaration.
 
                                                 Mahesh S
                                                 swatkat_thinkdigit@yahoo.co.in
                                                 http://swatrant.blogspot.com/


******************************************************************************/

#ifndef _PACKETFILTER_H_
#define _PACKETFILTER_H_

//#define SAMPLE_APP  // Comment this line to disable the main().

// Standard includes.
#include <Winsock2.h>
#include <conio.h>
#include <fwpmu.h>
#include <vector>

// Firewall sub-layer names.
#define FIREWALL_SUBLAYER_NAME  "OpenVPNFirewall"
#define FIREWALL_SUBLAYER_NAMEW L"OpenVPNFirewall"
#define FIREWALL_SERVICE_NAMEW  FIREWALL_SUBLAYER_NAMEW

struct ADDRMASK4 {
	uint32_t addr;
	uint32_t mask;
};

uint32_t IPv4(const PCSTR);

class PacketFilter
{
private:
	// Save filter IDs here
	std::vector<UINT64> filterids;
    // Firewall engine handle.
    HANDLE m_hEngineHandle;

    // Firewall sublayer GUID.
    GUID m_subLayerGUID;

    // Method to create/delete packet filter interface.
    DWORD CreateDeleteInterface( bool bCreate );

    // Method to bind/unbind to/from packet filter interface.
    DWORD BindUnbindInterface( bool bBind );

    // Method to add/remove filter.
    DWORD AddRemoveFilter( bool bAdd );

public:
	std::vector<uint64_t> tapluids;
	std::vector<ADDRMASK4> adapteripandmask4;
	std::vector<FWP_V6_ADDR_AND_MASK> adapteripandprefix6;

    // Constructor.
    PacketFilter();

    // Destructor.
    ~PacketFilter();

    // Method to start packet filter.
    BOOL StartFirewall();

    // Method to stop packet filter.
    BOOL StopFirewall();
};

#endif