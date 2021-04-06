#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Not working, because of...
# /dup_time.py", line 24, in <module>
# ModuleNotFoundError: No module named 'past'


include $(TOPDIR)/rules.mk

PKG_NAME:=duplicity
PKG_VERSION:=0.8.18
PKG_REV:=ec0079bb6ea7166ec0a1cc6223188523b3a9bca1
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://gitlab.com/duplicity/duplicity.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_MIRROR_HASH:=51419e5f7bf297b10959e74f3ab54261c81d8723a7c9d1d0146d94fb818e3416

include $(TOPDIR)/feeds/packages/lang/python/pypi.mk
include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/duplicity
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+python3-fasteners +python3-idna +python3-logging +python3-six +python3-urllib +librsync
	TITLE:=bandwidth-efficient backup
	URL:=http://duplicity.nongnu.org/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/duplicity/description
 Encrypted bandwidth-efficient backup using the rsync algorithm.
endef

$(eval $(call Py3Package,duplicity))
$(eval $(call BuildPackage,duplicity))
