#
# Copyright (C) 2011-2019 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# Remote DLNA server become visible. You can browse remote content but can't play on TV
# (Samsung TV says "Unsupported format")

include $(TOPDIR)/rules.mk

PKG_NAME:=dlnaproxy
PKG_VERSION:=1.0
PKG_REV:=f228e35c17b80d69911968902b079ffd403fef6a
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/zyclonite/dlnaproxy.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/dlnaproxy
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Web Servers/Proxies
	TITLE:=DLNA proxy
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/dlnaproxy/description
 DLNA proxy for routed networks not allowing multicast routing.
endef

define Package/dlnaproxy/conffiles
/opt/etc/dlnaproxy.conf
endef

define Package/dlnaproxy/install
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dlnaproxy $(1)/opt/sbin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/openwrt/files/dlnaproxy.conf $(1)/opt/etc
	$(INSTALL_BIN) files/S91dlnaproxy $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,dlnaproxy))
