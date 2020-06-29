#
# Copyright (C) 2011-2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It's working, but too heavy for embedded devices

include $(TOPDIR)/rules.mk

PKG_NAME:=btfs
PKG_VERSION:=2.1
PKG_REV:=260a603417cf498bc57fa37e43dc4f72fd144ac5
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/johang/btfs.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/btfs
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=BitTorrent
	DEPENDS:=+rblibtorrent +libcurl +libfuse +libatomic $(ICONV_DEPENDS)
	TITLE:=bittorrent filesystem
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/btfs/description
 With BTFS, you can mount any .torrent file or magnet link and then use it as
 any read-only directory in your file tree. The contents of the files will be
 downloaded on-demand as they are read by applications. Tools like ls,
 cat and cp works as expected. Applications like vlc and mplayer can also
 work without changes.
endef

TARGET_LDFLAGS += -liconv

define Package/btfs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/btfs{,stat} $(1)/opt/bin
endef

$(eval $(call BuildPackage,btfs))
