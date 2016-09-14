// Copyright 2016 Theo Schlossnagle. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build solaris

package net

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_types.h>
*/
import "C"

import (
	"syscall"
	"unsafe"
)

// If the ifindex is zero, interfaceTable returns mappings of all
// network interfaces. Otherwise it returns a mapping of a specific
// interface.
func interfaceTable(ifindex int) ([]Interface, error) {
	ifs, _, err := solaris_getallifaddrs(syscall.AF_UNSPEC, C.LIFC_ENABLED, ifindex)
	return ifs, err
}

// If the ifi is nil, interfaceAddrTable returns addresses for all
// network interfaces. Otherwise it returns addresses for a specific
// interface.
func interfaceAddrTable(ifi *Interface) ([]Addr, error) {
	retaddrs := make([]Addr, 0, 1)
	ifindex := 0
	if ifi != nil {
		ifindex = ifi.Index
	}
	_, addrs, err := solaris_getallifaddrs(syscall.AF_UNSPEC, C.LIFC_ENABLED, ifindex)
	for _, addr := range addrs {
		if addr != nil {
			retaddrs = append(retaddrs, addr[0])
		}
	}
	return retaddrs, err
}

// interfaceMulticastAddrTable returns addresses for a specific
// interface.
func interfaceMulticastAddrTable(ifi *Interface) ([]Addr, error) {
	return nil, nil
}

func uint32_Cdefine(in int32) uint32 {
	return *((*uint32)(unsafe.Pointer(&in)))
}

// solaris_getallifaddrs
func solaris_getallifaddrs(family int8, flags int32, ifindex int) ([]Interface, [][]Addr, error) {
	sock4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}
	defer syscall.Close(sock4)
	sock6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, err
	}
	defer syscall.Close(sock6)

	lifs, err := solaris_getallifs(sock4, family, flags&^C.LIFC_ENABLED)
	if err != nil {
		return nil, nil, err
	}

	ifs := make([]Interface, 0, len(lifs))
	addrs := make([][]Addr, 0, len(lifs))

	SIOCGLIFADDR := uint32_Cdefine(C.SIOCGLIFADDR)
	SIOCGLIFNETMASK := uint32_Cdefine(C.SIOCGLIFNETMASK)
	SIOCGLIFFLAGS := uint32_Cdefine(C.SIOCGLIFFLAGS)
	SIOCGLIFINDEX := uint32_Cdefine(C.SIOCGLIFINDEX)
	SIOCGLIFMTU := uint32_Cdefine(C.SIOCGLIFMTU)
	SIOCGLIFHWADDR := uint32_Cdefine(C.SIOCGLIFHWADDR)

	for _, lifr := range lifs {
		lifr_family := lifr.lifr_addr().ss_family
		if family != syscall.AF_UNSPEC && C.sa_family_t(family) != lifr_family {
			continue
		}
		s := -1
		switch int8(lifr_family) {
		case syscall.AF_INET:
			s = sock4
		case syscall.AF_INET6:
			s = sock6
		default:
			continue
		}
		lifrl := C.struct_lifreq{}
		lifrl.lifr_name = lifr.lifr_name

		// fetch flags
		if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFFLAGS), uintptr(unsafe.Pointer(&lifrl))); err != 0 {
			return ifs, addrs, err
		}
		if 0 != (flags&C.LIFC_ENABLED) && 0 == (lifrl.lifr_flags()&uint64(C.IFF_UP)) {
			continue
		}

		iface := Interface{Name: C.GoString((*C.char)(unsafe.Pointer(&lifr.lifr_name)))}
		if 0 != (lifrl.lifr_flags() & uint64(C.IFF_UP)) {
			iface.Flags |= FlagUp
		}
		if 0 != (lifrl.lifr_flags() & uint64(C.IFF_POINTOPOINT)) {
			iface.Flags |= FlagPointToPoint
		}
		if 0 != (lifrl.lifr_flags() & uint64(C.IFF_BROADCAST)) {
			iface.Flags |= FlagBroadcast
		}
		if 0 != (lifrl.lifr_flags() & uint64(C.IFF_LOOPBACK)) {
			iface.Flags |= FlagLoopback
		}
		if 0 != (lifrl.lifr_flags() & uint64(C.IFF_MULTICAST)) {
			iface.Flags |= FlagMulticast
		}

		// fetch index
		if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFINDEX), uintptr(unsafe.Pointer(&lifrl))); err != 0 {
			return ifs, addrs, err
		}
		iface.Index = int(lifrl.lifr_index())
		if ifindex != 0 && ifindex != iface.Index {
			continue
		}

		// If fetching the MTU fails, we don't bail
		if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFMTU), uintptr(unsafe.Pointer(&lifrl))); err == 0 {
			iface.MTU = int(lifrl.lifr_mtu())
		}
		// Likewise if fetching the hwaddr fails, we don't bail
		if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFHWADDR), uintptr(unsafe.Pointer(&lifrl))); err == 0 {
			dladdr := lifrl.lifr_dladdr()
			if lifrl.lifr_type == C.IFT_ETHER && dladdr.sdl_alen == 6 {
				octets := [6]uint8{}
				for i := 0; i < 6; i++ {
					octets[i] = *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&dladdr.sdl_data)) + uintptr(dladdr.sdl_nlen) + uintptr(i)))
				}
				iface.HardwareAddr = HardwareAddr(octets[:])
			}
		}

		addrlist := make([]Addr, 0, 1)
		if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFADDR), uintptr(unsafe.Pointer(&lifrl))); err == 0 {
			var ip IP
			var mask IPMask
			switch int(lifrl.lifr_addr().ss_family) {
			case syscall.AF_INET:
				ip4 := [4]byte{}
				for i := 0; i < 4; i++ {
					ip4[i] = *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&lifrl.lifr_addr4().sin_addr)) + uintptr(i)))
				}
				ip = IPv4(ip4[0], ip4[1], ip4[2], ip4[3])
				mask = CIDRMask(8*IPv4len, 8*IPv4len)
			case syscall.AF_INET6:
				ip = make(IP, IPv6len)
				copy(ip, lifrl.lifr_addr6().sin6_addr._S6_un[:])
				mask = CIDRMask(8*IPv6len, 8*IPv6len)
			}
			if err := syscall.Ioctl(uintptr(s), uintptr(SIOCGLIFNETMASK), uintptr(unsafe.Pointer(&lifrl))); err == 0 {
				switch int(lifrl.lifr_addr().ss_family) {
				case syscall.AF_INET:
					ip4 := [4]byte{}
					for i := 0; i < 4; i++ {
						ip4[i] = *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&lifrl.lifr_addr4().sin_addr)) + uintptr(i)))
					}
					mask = IPv4Mask(ip4[0], ip4[1], ip4[2], ip4[3])
				case syscall.AF_INET6:
					copy(mask, lifrl.lifr_addr6().sin6_addr._S6_un[:])
				}
			}
			addrlist = append(addrlist, &IPNet{IP: ip, Mask: mask})
		}

		addrs = append(addrs, addrlist)
		ifs = append(ifs, iface)
	}
	return ifs, addrs, nil
}
func (lifr *C.struct_lifreq) lifr_addr() *C.struct_sockaddr_storage {
	return (*C.struct_sockaddr_storage)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_addr4() *C.struct_sockaddr_in {
	return (*C.struct_sockaddr_in)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_addr6() *C.struct_sockaddr_in6 {
	return (*C.struct_sockaddr_in6)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_dladdr() *C.struct_sockaddr_dl {
	return (*C.struct_sockaddr_dl)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_flags() uint64 {
	return *(*uint64)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_index() int32 {
	return *(*int32)(unsafe.Pointer(&lifr.lifr_lifru))
}
func (lifr *C.struct_lifreq) lifr_mtu() uint32 {
	return *(*uint32)(unsafe.Pointer(&lifr.lifr_lifru))
}

// solaris_getallifs
func solaris_getallifs(socket int, family int8, flags int32) ([]C.struct_lifreq, error) {
	lifn := C.struct_lifnum{lifn_family: C.sa_family_t(family), lifn_flags: C.int(flags)}
	SIOCGLIFNUM := uint32_Cdefine(C.SIOCGLIFNUM)
	SIOCGLIFCONF := uint32_Cdefine(C.SIOCGLIFCONF)
	for {
		if err := syscall.Ioctl(uintptr(socket), uintptr(SIOCGLIFNUM), uintptr(unsafe.Pointer(&lifn))); err != 0 {
			return nil, err
		}
		cnt := lifn.lifn_count + 4
		buf := C.malloc(C.size_t(cnt * C.sizeof_struct_lifreq))
		lifc := C.struct_lifconf{
			lifc_family: C.sa_family_t(family),
			lifc_flags:  C.int(lifn.lifn_flags),
			lifc_len:    cnt * C.sizeof_struct_lifreq,
		}
		*(*uintptr)(unsafe.Pointer(&lifc.lifc_lifcu)) = uintptr(buf)
		defer C.free(buf)
		if err := syscall.Ioctl(uintptr(socket), uintptr(SIOCGLIFCONF), uintptr(unsafe.Pointer(&lifc))); err != 0 {
			return nil, err
		}
		if n := lifc.lifc_len / C.sizeof_struct_lifreq; n < cnt {
			// It fit... process
			names := make([]C.struct_lifreq, n)
			for i := 0; i < int(n); i++ {
				ifn := (*C.struct_lifreq)(unsafe.Pointer(uintptr(buf) + uintptr(i)*C.sizeof_struct_lifreq))
				names[i] = *ifn
			}
			return names, nil
		}
		break
	}
	return nil, nil
}
