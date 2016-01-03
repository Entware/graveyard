#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pycparser
PKG_VERSION:=2.14
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/source/p/pycparser
PKG_MD5SUM:=a2bc8d28c923b4fe2b2c3b4b51a4f935

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/$(PKG_NAME)
	SUBMENU:=Python
	SECTION:=lang
	CATEGORY:=Languages
	TITLE:=ASN.1 types and codecs
	URL:=https://github.com/eliben/pycparser
	DEPENDS:=+python
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/$(PKG_NAME)/description
 pycparser is a complete parser of the C language, written in pure Python using
 the PLY parsing library. It parses C code into an AST and can serve as a
 front-end for C compilers or analysis tools.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install \
		--prefix=/opt \
		--root="$(PKG_INSTALL_DIR)" \
	)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
