#
# Copyright (C) 2011-2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It works, but causes OOM even on devices with 256MB RAM

include $(TOPDIR)/rules.mk

PKG_NAME:=btfs
PKG_VERSION:=2.22
PKG_RELEASE=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/johang/btfs.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=3b5e4a8a7eb13a4dbd15ae1aac70220aa08d1748
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/btfs
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=BitTorrent
	DEPENDS:=+rblibtorrent +libfuse +libcurl +libatomic
	TITLE:=a bittorrent filesystem based on FUSE
	URL:=
endef

define Package/btfs/description
 With BTFS, you can mount any .torrent file or magnet link and then use it
 as any read-only directory in your file tree. The contents of the files
 will be downloaded on-demand as they are read by applications. Tools like
 ls, cat and cp works as expected.
endef


define Package/btfs/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/btfs* $(1)/opt/bin
endef

$(eval $(call BuildPackage,btfs))
