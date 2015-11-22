#
# Copyright (C) 2011-2013 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=encfs
PKG_REV:=93
PKG_VERSION:=2.0-r$(PKG_REV)
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=svn
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=http://encfs.googlecode.com/svn/trunk/
PKG_SOURCE:=$(PKG_SOURCE_SUBDIR).tar.gz

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/encfs
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=Filesystem
#	DEPENDS:=+glog +tinyxml
	TITLE:=an encrypted filesystem in user-space.
	URL:=http://www.arg0.net/encfs
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/encfs/description
 EncFS provides an encrypted filesystem in user-space. It runs without any
 special permissions and uses the FUSE library and Linux kernel module
 to provide the filesystem interface.
endef

define Package/encfs/install
	$(INSTALL_DIR) $(1)/opt/sbin
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/sbin/encfsd $(1)/opt/sbin/
endef

$(eval $(call BuildPackage,encfs))
