#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Partially taken from https://github.com/Alberts00/OpenWRT-package-softether

# tmp/hamcorebuilder host-utility requres bunch of additional dependencies
# to host system. So it's still not cross-compilation friendly.

include $(TOPDIR)/rules.mk

PKG_NAME:=softethervpn
PKG_VERSION:=v4.21-9613-beta
PKG_REV:=1e17c9bcfd7e7b31756aa5389bcbff76c2c9c88a
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/SoftEtherVPN/SoftEtherVPN.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

#PKG_INSTALL:=1
PKG_BUILD_DEPENDS:=softethervpn/host

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package.mk

define Package/softethervpn
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=VPN
#	DEPENDS:=+libsodium
	TITLE:=softethervpn
	URL:=http://www.softether.org/
	MAINTAINER:=Entware team, entware.net
endef

define Package/softethervpn/description
 A Free Cross-platform Multi-protocol VPN Software, developed by SoftEther VPN
 Project at University of Tsukuba, Japan.
endef

ifeq ($(ARCH),x86_64)
  SE_MAKEFILE=linux_64bit.mak
else
  SE_MAKEFILE=linux_32bit.mak
endif

define Host/Compile
	$(MAKE) $(HOST_JOBS) -C $(HOST_BUILD_DIR) src/bin/BuiltHamcoreFiles/unix/hamcore.se2
endef

define Host/Install
endef

define Build/Configure
    $(CP) $(PKG_BUILD_DIR)/src/makefiles/$(SE_MAKEFILE) $(PKG_BUILD_DIR)/Makefile
endef

MAKE_FLAGS += \
	CCFLAGS="$(TARGET_CPPFLAGS)"

define Package/softethervpn/conffiles
/opt/etc/softethervpn/client_down.sh
endef

define Package/softethervpn/install
	$(INSTALL_DIR) $(1)/opt/bin
endef

$(eval $(call HostBuild))
$(eval $(call BuildPackage,softethervpn))
