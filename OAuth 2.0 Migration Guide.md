# OAuth 2.0 迁移指南

这篇文档包含了OAuth2 客户端以及资源服务器从Spring Security  OAuth 2.x迁移到Spring Security 5.2.x 指南。因为Spring Security 并不提供授权服务器支持，迁移Spring Security OAuth2 授权服务器不在本文的范围内。

由于这两种方法各不相同，因此本文档将倾向于涵盖更多模式，而不是精确的搜索和替换步骤。

## 客户端

### 方法的变化

#### 简化启用

#### 一个简化的 RestTemplate 和 WebClient

#### 简化的客户端解析

#### 增强的客户端注册

#### 简化的 JWT 支持

### 示例矩阵

## 登录

### 方法的变化

#### 简化启用

## 资源服务器

### 方法的变化

#### 简化启用

#### 简化的DSL

#### 简化启用

#### 简化的授权配置

### 示例矩阵

### 未移植的功能

我们目前没有计划移植一些功能。

在 Spring Security OAuth 中，您可以配置 UserDetailsService 来查找与传入的不记名令牌对应的用户。 Spring Security 的资源服务器支持没有计划选择 UserDetailsService。不过，通过 jwtAuthenticationConverter DSL 方法，这在 Spring Security 中仍然很简单。值得注意的是，可以返回一个 BearerTokenAuthentication ，它采用 OAuth2AuthenticatedPrincipal 的实例作为主体。

在 Spring Security OAuth 中，您可以通过 ResourceServerSecurityConfigurer#resourceId 方法为资源服务器分配一个标识符。这将配置身份验证入口点使用的领域名称并添加受众验证。没有为 Spring Security 计划这样的标识符。但是，通过分别配置 OAuth2TokenValidator 和 AuthenticationEntryPoint，受众验证和自定义领域名称都很容易实现。











