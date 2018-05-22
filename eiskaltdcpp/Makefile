#
# Copyright (C) 2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Only UTF8 chat support, no any filelist can be downloaded

include $(TOPDIR)/rules.mk

PKG_NAME:=eiskaltdcpp
PKG_VERSION:=2.3.0-20180301
PKG_REV:=1e72256ac5e8fe6735f81bfbc3f9d90514ada578
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/eiskaltdcpp/eiskaltdcpp.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/eiskaltdcpp
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=P2P
	TITLE:=eiskaltdcpp is a modern and lightweight Direct Connect and ADC client
	DEPENDS:=+boost-system +libopenssl +libbz2 +libidn
	URL:=https://github.com/eiskaltdcpp/eiskaltdcpp
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/eiskaltdcpp/description
 EiskaltDC++ is a cross-platform program that uses the Direct Connect and ADC
 protocols. It is compatible with DC++, FlylinkDC++, LinuxDC++ and other DC
 clients. EiskaltDC++ also interoperates with all common DC hub software.
endef

TARGET_LDFLAGS += \
	-lpthread

CMAKE_OPTIONS += \
	-DUSE_QT5=OFF \
	-DFREE_SPACE_BAR_C=OFF \
	-DNO_UI_DAEMON=ON \
	-DJSONRPC_DAEMON=ON \
	-DUSE_CLI_XMLRPC=ON \
	-DUSE_CLI_JSONRPC=ON \
	-DWITH_EMOTICONS=OFF \
	-DWITH_EXAMPLES=OFF \
	-DWITH_LUASCRIPTS=ON \
	-Dlinguas="" \
	-DFORCE_XDG=OFF

define Package/eiskaltdcpp/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/eiskaltdcpp-daemon $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/lib/libeiskaltdcpp.so* $(1)/opt/lib
endef

$(eval $(call BuildPackage,eiskaltdcpp))
