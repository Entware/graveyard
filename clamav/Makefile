#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It works, but it't too heavy for MIPS devices

include $(TOPDIR)/rules.mk

PKG_NAME:=clamav
PKG_VERSION:=0.97.6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/$(PKG_NAME)
PKG_MD5SUM:=1dbdd803b37c0d9d222e4316049f46a2

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/clamav
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libbz2 +libncurses +libpthread +libltdl +zlib $(ICONV_DEPENDS)
	TITLE:=ClamAV antivirus
	URL:=http://www.clamav.net
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/clamav/description
 ClamAV is an open source (GPL) antivirus engine designed for detecting Trojans,
 viruses, malware and other malicious threats.
endef

CONFIGURE_ARGS += \
	--disable-clamav \
	--with-user=root \
	--with-group=root \
	--enable-clamdtop \
	--disable-llvm \
	--with-zlib=$(STAGING_DIR)/opt \
	--with-libbz2-prefix=$(STAGING_DIR)/opt \
	--with-iconv \
	--with-libncurses-prefix=$(STAGING_DIR)/opt \

define Package/clamav/conffiles
/opt/etc/clamd.conf
/opt/etc/freshclam.conf
endef

define Package/clamav/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/clam{bc,conf,dscan,dtop,scan} \
		$(PKG_INSTALL_DIR)/opt/bin/{freshclam,sigtool} \
		$(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/opt/etc/{clamd,freshclam}.conf \
		 $(1)/opt/etc
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libclam*.so* \
		 $(1)/opt/lib
	$(INSTALL_DIR) $(1)/opt/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/sbin/clamd \
		 $(1)/opt/sbin
	$(INSTALL_DIR) $(1)/opt/share/clamav
endef

$(eval $(call BuildPackage,clamav))
