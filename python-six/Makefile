#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-six
PKG_VERSION:=1.9.0
PKG_RELEASE:=1

PKG_SOURCE:=six-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/source/s/six
PKG_MD5SUM:=476881ef4012262dfc8adc645ee786c4

PKG_BUILD_DIR:=$(BUILD_DIR)/six-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/$(PKG_NAME)
	SUBMENU:=Python
	SECTION:=lang
	CATEGORY:=Languages
	TITLE:=Python 2 and 3 compatibility utilities
	URL:=http://pypi.python.org/pypi/six/
	DEPENDS:=+python
	MAINTAINER:=Entware team, entware.wl500g.info
endef

define Package/$(PKG_NAME)/description
 Six is a Python 2 and 3 compatibility library. It provides utility functions
 for smoothing over the differences between the Python versions with the goal
 of writing Python code that is compatible on both Python versions.
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
