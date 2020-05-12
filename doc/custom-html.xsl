<?xml version='1.0'?> <!--*-nxml-*-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ss="http://docbook.sf.net/xmlns/string.subst/1.0"
  xmlns:exsl="http://exslt.org/common" version="1.0">

  <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>
  <xsl:param name="vendordir"/>

  <xsl:template match="filename">
    <xsl:variable name="replacements">
      <ss:substitution oldstring="%vendordir%" newstring="{$vendordir}" />
    </xsl:variable>
    <xsl:call-template name="apply-string-subst-map">
      <xsl:with-param name="content" select="."/>
      <xsl:with-param name="map.contents" select="exsl:node-set($replacements)/*" />
    </xsl:call-template>
  </xsl:template>
</xsl:stylesheet>
