#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=trafshow
PKG_VERSION:=5.2.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).orig.tar.gz
PKG_SOURCE_URL:=ftp://ftp.ubuntu.com/ubuntu/pool/universe/t/$(PKG_NAME)
PKG_MDSUM:=2905aff7a58812a9954caebde705005d

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/trafshow
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpcap
	TITLE:=full screen show network traffic
	URL:=http://soft.risp.ru/trafshow/index.shtml
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/trafshow/description
 TrafShow continuously display the information regarding packet traffic on the
 configured network interface.
endef

TARGET_CFLAGS := $(TARGET_CPPFLAGS)

define Package/trafshow/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/{trafshow,bxcommit,bximage} \
		$(1)/opt/bin/
endef

$(eval $(call BuildPackage,trafshow))
