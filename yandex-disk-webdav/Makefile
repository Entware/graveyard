#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=yandex-disk-webdav
PKG_VERSION:=0.2.11
PKG_REV:=a5edd53c67c9d188d0f632a509ccac245527190f
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/lexich/yandex-disk-webdav.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/yandex-disk-webdav
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=File Transfer
	DEPENDS:=+simplejson +python-six +python-openssl +python-expat
	TITLE:=Yandex.Disk python wrapper
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/yandex-disk-webdav/description
 Simple wrapper to work with yandex disk using webdav Basic Auth.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix=/opt --root=$(PKG_INSTALL_DIR))
endef

define Package/yandex-disk-webdav/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ydw.py $(1)/opt/bin
endef

$(eval $(call BuildPackage,yandex-disk-webdav))
