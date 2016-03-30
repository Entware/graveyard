#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=irssi
PKG_VERSION:=0.8.19
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/irssi/irssi/releases/download/$(PKG_VERSION)
PKG_MD5SUM:=759af618f506e85bd66862f83d8a4f9a

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/irssi/Default
  SUBMENU:=Instant Messaging
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+glib2 +libncurses +perl
  TITLE:=Console IRC client
  MAINTAINER:=Peter Wagner <tripolar@gmx.at>
  URL:=http://irssi.org/
endef

define Package/irssi/Default/description
	Irssi is a terminal based IRC client for UNIX systems.
endef

define Package/irssi
$(call Package/irssi/Default)
  TITLE+= (with OpenSSL support)
  DEPENDS+= +libopenssl
  VARIANT:=ssl
endef

define Package/irssi/description
$(call Package/irssi/Default/description)
 This package is built with OpenSSL support.
endef

define Package/irssi-nossl
$(call Package/irssi/Default)
  TITLE+= (without OpenSSL support)
  VARIANT:=nossl
endef

define Package/irssi-nossl/description
$(call Package/irssi/Default/description)
 This package is built without OpenSSL support.
endef

PERL_SITE="/opt/lib/perl5/5.22"

CONFIGURE_VARS += \
	PERL_CFLAGS="-D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I$(STAGING_DIR)/opt/lib/perl5/5.22/CORE" \
	PERL_LDFLAGS="-L$(STAGING_DIR)$(PERL_SITE)/CORE -lperl" \
	PERL_USE_LIB="$(PERL_SITE)"

CONFIGURE_ARGS += \
	--with-perl-lib="$(PERL_SITE)" \
	--with-perl=yes \
	--with-ncurses="$(STAGING_DIR)/opt" \
	--with-textui \
	--with-bot

EXTRA_CFLAGS+=$(TARGET_CPPFLAGS)
EXTRA_LDFLAGS+=-lncurses

ifeq ($(BUILD_VARIANT),nossl)
	CONFIGURE_ARGS += \
		--disable-ssl
endif

define Package/irssi/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/$(PKG_NAME) $(1)/opt/bin/$(PKG_NAME)
endef

Package/irssi-nossl/install = $(Package/irssi/install)

$(eval $(call BuildPackage,irssi))
$(eval $(call BuildPackage,irssi-nossl))
