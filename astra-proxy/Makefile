#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# MIPS binary just hangs on start with...
# INFO: [main] Starting Astra v.4.188
# ...message. No any network activity produced, no any socket opened.

include $(TOPDIR)/rules.mk

PKG_NAME:=astra-proxy
PKG_VERSION:=4.188
PKG_REV:=5f977d65df48915d57326ada89207b19fa8c499b
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://bitbucket.org/cesbo/astra.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/astra-proxy
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpthread +librt
	TITLE:=сonvert UDP IPTV streams into HTTP streams
	URL:=https://cesbo.com/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/astra-proxy/description
 Astra (Advanced Streamer) makes it possible to convert
 UDP IPTV streams into HTTP streams.
endef

define Build/Configure
	(cd $(PKG_BUILD_DIR); \
	    ./configure.sh \
		--cc="$(TARGET_CC)" \
		--cflags="$(TARGET_CFLAGS)" \
		--ldflags="$(TARGET_LDFLAGS)"; \
	)
endef

define Package/astra-proxy/postinst
#!/bin/sh
cat << EOF
Start options can be adjusted via /opt/etc/init.d/S29astra.
See https://cesbo.com/en/astra/quick-start/#launch for details
EOF
endef

define Package/astra-proxy/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/astra $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) ./files/S29astra $(1)/opt/etc/init.d
endef

$(eval $(call BuildPackage,astra-proxy))
