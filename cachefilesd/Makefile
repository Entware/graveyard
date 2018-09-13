#
# Copyright (C) 2011-2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cachefilesd
PKG_VERSION:=0.10.10
PKG_REV:=f28c4e141af446487c7ab01fcb7832e5823c13e2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/cachefilesd.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/cachefilesd
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=Filesystem
	TITLE:=CacheFiles userspace management daemon
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/cachefilesd/description
 The cachefilesd daemon manages the cache data store that is used by network
 filesystems such a AFS and NFS to cache data locally on disk.
endef

define Package/cachefilesd/conffiles
/opt/etc/cachefilesd.conf
endef

define Package/cachefilesd/install
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/opt/sbin
	$(INSTALL_DIR) $(1)/opt/etc
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/$(PKG_NAME).conf $(1)/opt/etc
	$(INSTALL_DIR) $(1)/opt/var/cache/fscache
endef

$(eval $(call BuildPackage,cachefilesd))
