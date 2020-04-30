#
# Copyright (C) 2011-2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# It's a working package with no national symbols support

include $(TOPDIR)/rules.mk

PKG_NAME:=calcurse
PKG_VERSION:=4.6.0
PKG_REV:=5a3664bf73dab84561bb03db0fe64e275a270093
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/lfos/calcurse.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/calcurse
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libncursesw
	TITLE:=text-based calendar and scheduling app
	URL:=https://calcurse.org/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/calcurse/description
 CalCurse is a calendar and todo list for the console which allows
 you to keep track of your appointments and everyday tasks. CalCurse
 has a nice textmode interface with configurable color schemes, configurable
 layout and Vi-like keybindings.
endef

CONFIGURE_ARGS += \
	--disable-docs \
	--with-libiconv-prefix="$(ICONV_PREFIX)" \
	--with-libintl-prefix="$(INTL_PREFIX)" \
	--without-asciidoc

define Package/calcurse/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/calcurse $(1)/opt/bin
endef

$(eval $(call BuildPackage,calcurse))
