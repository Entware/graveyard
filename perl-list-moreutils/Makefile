#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

#This package needs http://search.cpan.org/~tobyink/Exporter-Tiny-0.042/lib/Exporter/Tiny.pm

include $(TOPDIR)/rules.mk

PKG_NAME:=perl-list-moreutils
PKG_VERSION:=0.413
PKG_RELEASE:=1

PKG_SOURCE_URL:=http://www.cpan.org/authors/id/R/RE/REHSACK/
PKG_SOURCE:=List-MoreUtils-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=ecfd0eeb88512033352c2f13c9580f03

PKG_LICENSE:=GPL-1.0+ Artistic-1.0-Perl

PKG_BUILD_DIR:=$(BUILD_DIR)/perl/List-MoreUtils-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include ../perl/perlmod.mk

define Package/perl-list-moreutils
  SUBMENU:=Perl
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Provide the stuff missing in List::Util
  URL:=http://search.cpan.org/~rehsack/List-MoreUtils-0.413/lib/List/MoreUtils.pm
  DEPENDS:=perl +perlbase-essential +perlbase-base +perlbase-xsloader +perlbase-file +perlbase-ipc +perlbase-test
endef

define Build/Configure
        $(call perlmod/Configure,,)
endef

define Build/Compile
        $(call perlmod/Compile,,)
endef

define Package/perl-list-moreutils/install
        $(call perlmod/Install,$(1),List List/MoreUtils auto/List/MoreUtils)
endef


$(eval $(call BuildPackage,perl-list-moreutils))
