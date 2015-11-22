#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=hadouken
PKG_VERSION:=5.2.0-20150926
PKG_REV:=1928a95158b2ba726641abdc09d801e24fbd1cf9
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/hadouken/hadouken.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/hadouken
	SUBMENU:=BitTorrent
	SECTION:=net
	CATEGORY:=Network
	TITLE:=a headless BitTorrent client
	URL:=$(PKG_SOURCE_URL)
	DEPENDS:=+rblibtorrent
	MAINTAINER:=Entware team, entware.wl500g.info
endef

define Package/hadouken/description
 Hadouken a cross-platform, headless BitTorrent client with low memory footprint.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(RM) -fr $(PKG_BUILD_DIR)/deps/libtorrent
#	for srcfile in `find $(PKG_BUILD_DIR) -type f`; do \
#	    $(SED) 's|\r||g' $$$$srcfile; \
#	done;
endef

#	for srcfile in `find $(PKG_BUILD_DIR) -name *.?pp`; do \

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/opt/include \
	-D_GLIBCXX_USE_C99 \
	-std=c++11

#[100%] Linking CXX executable bin/hadouken
#CMakeFiles/hadouken.dir/src/application.cpp.o: In function `hadouken::application::application(boost::shared_ptr<boost::asio::io_service>, boost::property_tree::basic_ptree<std::string, std::string, std::less<std::string> > const&)':
#application.cpp:(.text+0xb30): undefined reference to `libtorrent::clocktime_nodeprecate_()'

define Package/hadouken/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/hadouken $(1)/opt/bin/
endef

$(eval $(call BuildPackage,hadouken))
