#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tinyxml
PKG_VERSION:=2.6.2
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)_2_6_2.zip
PKG_SOURCE_URL:=@SF/$(PKG_NAME)/$(PKG_NAME)/$(PKG_VERSION)
PKG_MD5SUM:=2a0aaf609c9e670ec9748cd01ed52dae

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/tinyxml
	SECTION:=libs
	CATEGORY:=Libraries
	DEPENDS:=+libstdcpp
	TITLE:=C++ XML parser
	URL:=http://www.grinninglizard.com/tinyxml/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/tinyxml/description
 TinyXML is a simple, small, minimal, C++ XML parser that can be easily
 integrating into other programs. It reads XML and creates C++ objects
 representing the XML document.
endef

MAKE_VARS += \
	TINYXML_USE_STL=YES

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include/tinyxml
	$(CP) $(PKG_BUILD_DIR)/tiny{xml,str}.h $(1)/opt/include/tinyxml
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_BUILD_DIR)/libtinyxml.a $(1)/opt/lib
	$(INSTALL_DIR) $(1)/opt/lib/pkgconfig
	$(CP) ./files/tinyxml.pc $(1)/opt/lib/pkgconfig
endef

$(eval $(call BuildPackage,tinyxml))
