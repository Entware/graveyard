#
# Copyright (C) 2011-2013 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=newsbeuter
PKG_VERSION:=2.6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.newsbeuter.org/downloads/
PKG_MDSUM:=4a36627c5fabca6b2718a0ac78e6666f

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/newsbeuter
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=$(ICONV_DEPENDS) $(INTL_DEPENDS) +json-c +libstfl +libsqlite3 +libcurl +libxml2 libstdcpp
	TITLE:=RSS feeds reader
	URL:=http://www.newsbeuter.org/
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/newsbeuter/description
  Newsbeuter is an open-source RSS/Atom feed reader for text terminals. 
  Newsbeuter's great configurability and vast number of features make it 
  a perfect choice for people that need a slick and fast feed reader that can be completely controlled via keyboard.
endef

TARGET_LDFLAGS += -liconv -lintl
MAKE_FLAGS += \
	prefix=/opt \

define Package/newsbeuter/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/*beuter $(1)/opt/bin/
	$(INSTALL_DIR) $(1)/opt/share/doc/newsbeuter
	$(CP) $(PKG_INSTALL_DIR)/opt/share/doc/newsbeuter/* $(1)/opt/share/doc/newsbeuter
	$(INSTALL_DIR) $(1)/opt/share/locale
	$(CP) $(PKG_INSTALL_DIR)/opt/share/locale/* $(1)/opt/share/locale
	$(INSTALL_DIR) $(1)/opt/etc/.newsbeuter
	$(CP) $(PKG_INSTALL_DIR)/opt/share/doc/newsbeuter/examples/config $(1)/opt/etc/.newsbeuter
endef

$(eval $(call BuildPackage,newsbeuter))
