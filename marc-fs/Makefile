#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Works (probably works) with @mail.ru domain only, which is hardcoded.

include $(TOPDIR)/rules.mk

PKG_NAME:=marc-fs
PKG_VERSION:=0.4-20171029
PKG_REV:=146c97418740bb901348c0caddd798c6728dcf81
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://gitlab.com/Kanedias/MARC-FS.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/marc-fs
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Filesystem
	TITLE:=FUSE filesystem attempt for Mail.Ru Cloud
	URL:=https://gitlab.com/Kanedias/MARC-FS
	DEPENDS:=+jsoncpp +libcurl +libfuse +ca-certificates
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/marc-fs/description
 FUSE filesystem attempt for Mail.Ru Cloud
endef

TARGET_LDFLAGS += -lpthread

define Package/marc-fs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/marcfs $(1)/opt/bin
endef

$(eval $(call BuildPackage,marc-fs))
