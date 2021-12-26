#  OAuth2

Spring Security 提供了完整的OAuth 2支持.这部分内容讲的是如何把OAuth集成到基于Servlet的应用.

## OAuth2 登录

OAuth 2.0 登录特性给应用提供了让用户使用已有账号登录的能力,例如GitHub和Google的账号。OAuth 2.0登录实现的就是

使用Google登录或是使用GitHub登录的用例。

  OAuth 2.0登录是使用授权码模式实现的，正如[OAuth 2.0 授权框架](https://tools.ietf.org/html/rfc6749#section-4.1)以及[OPenID Connect 核心 1.0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)所说明的那样。

### 核心配置

#### Spring Boot 2.0 样例

Spring Boot 2.x 为OAuth 2.0 登录提供完全的自动配置能力.

这部分内容展示了[OAuth 2.0 登录样例](https://github.com/spring-projects/spring-security-samples/tree/main/servlet/spring-boot/java/oauth2/login)是如何使用Google作为认证服务提供者的.

##### 初始化

为了把Google 2.0认证系统用作登录，你必须在Ｇoogle API控制台设置好一个项目，从而你才能获取OAuth2.0凭证。

注意，[Google的OAuth 2.0认证实现]()是遵循 OpenID 连接1.0标准的规范的并且是[OpenID认证的](https://openid.net/certification/).

按照OpenID 连接页面上的指示，找到　"Setting up OAuth 2.0"

在完成 Obtain OAuth 2.0 credentials 指令之后，你现在有了一个新的由Client ID和Client Secret组成的ＯAuth 客户端。

##### 设置重定向URI

重定向 URI 是应用程序中的路径，最终用户的用户代理在他们通过 Google 进行身份验证并在同意页面上授予对 OAuth 客户端（在上一步中创建）的访问权限后重定向回该路径。

在“设置重定向 URI”子部分中，确保授权重定向 URI 字段设置为 http://localhost:8080/login/oauth2/code/google。

默认重定向 URI 模板为 {baseUrl}/login/oauth2/code/{registrationId}。 registrationId 是 ClientRegistration 的唯一标识符。

##### 配置application.yml

现在你有了一个新的 Google OAuth 客户端，您需要配置应用程序以使用 OAuth 客户端进行身份验证流。这样做：

转到 application.yml 并设置以下配置：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:	
          google:	
            client-id: google-client-id
            client-secret: google-client-secret
```

例1. OAuth 客户端属性

1. spring.security.oauth2.client.registration 是 OAuth 客户端属性的基本属性前缀。 
2. 在基本属性前缀之后是 ClientRegistration 的 ID，例如 google。

##### 启动应用

启动 Spring Boot 2.x 示例并转到 http://localhost:8080。然后，您将被重定向到默认的自动生成的登录页面，该页面显示 Google 的链接。 单击 Google 链接，然后您将被重定向到 Google 进行身份验证。 使用您的 Google 帐户凭据进行身份验证后，显示给您的下一页是同意屏幕。同意屏幕要求您允许或拒绝访问您之前创建的 OAuth 客户端。单击允许以授权 OAuth 客户端访问您的电子邮件地址和基本配置文件信息。 此时，OAuth 客户端会从 UserInfo 端点检索您的电子邮件地址和基本配置文件信息，并建立经过身份验证的会话。

#### Spring Boot 2.0属性对照表

| Spring Boot 2.x                                              | ClientRegistration                                       |
| :----------------------------------------------------------- | :------------------------------------------------------- |
| `spring.security.oauth2.client.registration.*[registrationId]*` | `registrationId`                                         |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-id` | `clientId`                                               |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-secret` | `clientSecret`                                           |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-authentication-method` | `clientAuthenticationMethod`                             |
| `spring.security.oauth2.client.registration.*[registrationId]*.authorization-grant-type` | `authorizationGrantType`                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.redirect-uri` | `redirectUri`                                            |
| `spring.security.oauth2.client.registration.*[registrationId]*.scope` | `scopes`                                                 |
| `spring.security.oauth2.client.registration.*[registrationId]*.client-name` | `clientName`                                             |
| `spring.security.oauth2.client.provider.*[providerId]*.authorization-uri` | `providerDetails.authorizationUri`                       |
| `spring.security.oauth2.client.provider.*[providerId]*.token-uri` | `providerDetails.tokenUri`                               |
| `spring.security.oauth2.client.provider.*[providerId]*.jwk-set-uri` | `providerDetails.jwkSetUri`                              |
| `spring.security.oauth2.client.provider.*[providerId]*.issuer-uri` | `providerDetails.issuerUri`                              |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-uri` | `providerDetails.userInfoEndpoint.uri`                   |
| `spring.security.oauth2.client.provider.*[providerId]*.user-info-authentication-method` | `providerDetails.userInfoEndpoint.authenticationMethod`  |
| `spring.security.oauth2.client.provider.*[providerId]*.user-name-attribute` | `providerDetails.userInfoEndpoint.userNameAttributeName` |

通过指定 spring.security.oauth2.client.provider.[providerId].issuer-uri 属性，可以使用 OpenID Connect Provider 的 Configuration 端点或 Authorization Server 的 Metadata 端点的发现来初始配置 ClientRegistration。

#### CommonOAuth2Provider

CommonOAuth2Provider 为许多知名提供商预定义了一组默认客户端属性：Google、GitHub、Facebook 和 Okta。 例如，provider 的 authorization-uri、token-uri 和 user-info-uri 不会经常更改。因此，提供默认值以减少所需的配置是有意义的。 如前所述，当我们配置 Google 客户端时，只需要 client-id 和 client-secret 属性。 以下清单显示了一个示例：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: google-client-id
            client-secret: google-client-secret
```

客户端属性的自动默认设置在这里可以无缝工作，因为 registrationId (google) 与 CommonOAuth2Provider 中的 GOOGLE 枚举（不区分大小写）匹配。

对于您可能想要指定不同的 registrationId（例如 google-login）的情况，您仍然可以通过配置 provider 属性来利用客户端属性的自动默认设置。 以下清单显示了一个示例：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google-login:	
            provider: google	
            client-id: google-client-id
            client-secret: google-client-secret
```

registrationId 设置为 google-login。 provider 属性设置为 google，这将利用 CommonOAuth2Provider.GOOGLE.getBuilder() 中设置的客户端属性的自动默认设置。

#### 配置自定义提供者属性

有一些 OAuth 2.0 提供者支持多租户，这会导致每个租户（或子域）的协议端点不同。 例如，在 Okta 注册的 OAuth 客户端被分配到特定的子域并拥有自己的协议端点。 对于这些情况，Spring Boot 2.x 提供了以下用于配置自定义提供程序属性的基本属性：spring.security.oauth2.client.provider.[providerId]。 以下清单显示了一个示例：

```
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-secret: okta-client-secret
        provider:
          okta:	
            authorization-uri: https://your-subdomain.oktapreview.com/oauth2/v1/authorize
            token-uri: https://your-subdomain.oktapreview.com/oauth2/v1/token
            user-info-uri: https://your-subdomain.oktapreview.com/oauth2/v1/userinfo
            user-name-attribute: sub
            jwk-set-uri: https://your-subdomain.oktapreview.com/oauth2/v1/keys
```

基本属性 (spring.security.oauth2.client.provider.okta) 允许自定义配置协议端点位置。

#### 覆盖Spring Boot 2.x 自动配置

用于 OAuth 客户端支持的 Spring Boot 2.x 自动配置类是 OAuth2ClientAutoConfiguration。 它执行以下任务： 从配置的 OAuth 客户端属性注册由 ClientRegistration(s) 组成的 ClientRegistrationRepository @Bean。 提供 WebSecurityConfigurerAdapter @Configuration 并通过 httpSecurity.oauth2Login() 启用 OAuth 2.0 登录。 如果您需要根据您的特定要求覆盖自动配置，您可以通过以下方式进行： 注册一个 ClientRegistrationRepository @Bean 提供一个 WebSecurityConfigurerAdapter 完全覆盖自动配置

##### 注册一个ClientRegistrationRepository @Bean

以下示例显示了如何注册 ClientRegistrationRepository @Bean：

```java
@Configuration
public class OAuth2LoginConfig {

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	}

	private ClientRegistration googleClientRegistration() {
		return ClientRegistration.withRegistrationId("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid", "profile", "email", "address", "phone")
			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
			.userNameAttributeName(IdTokenClaimNames.SUB)
			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
			.clientName("Google")
			.build();
	}
}
```



##### 提供一个WebSecurityConfigurerAdapter

下面的例子展示了如何提供一个带有@EnableWebSecurity 的 WebSecurityConfigurerAdapter 并通过 httpSecurity.oauth2Login() 启用 OAuth 2.0 登录：

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login(withDefaults());
	}
}
```

示例 2. OAuth2 登录配置

##### 完全覆盖自动配置

以下示例显示了如何通过注册 ClientRegistrationRepository @Bean 并提供 WebSecurityConfigurerAdapter 来完全覆盖自动配置。

```java
@Configuration
public class OAuth2LoginConfig {

	@EnableWebSecurity
	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeHttpRequests(authorize -> authorize
					.anyRequest().authenticated()
				)
				.oauth2Login(withDefaults());
		}
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	}

	private ClientRegistration googleClientRegistration() {
		return ClientRegistration.withRegistrationId("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid", "profile", "email", "address", "phone")
			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
			.userNameAttributeName(IdTokenClaimNames.SUB)
			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
			.clientName("Google")
			.build();
	}
}
```



示例 3. 覆盖自动配置

#### 非Spring Boot 2.x项目的Java配置

````java
@Configuration
public class OAuth2LoginConfig {

	@EnableWebSecurity
	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeHttpRequests(authorize -> authorize
					.anyRequest().authenticated()
				)
				.oauth2Login(withDefaults());
		}
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService(
			ClientRegistrationRepository clientRegistrationRepository) {
		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
	}

	@Bean
	public OAuth2AuthorizedClientRepository authorizedClientRepository(
			OAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}

	private ClientRegistration googleClientRegistration() {
		return CommonOAuth2Provider.GOOGLE.getBuilder("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.build();
	}
}
````

### 高级配置

HttpSecurity.oauth2login() 提供了一些自定义OAuth 2.0 登录的配置项.主要的配置选项按照它们协议的端点分成了几个部分.

例如,oauth2Login.authorizationEndpoint()可以对授权端点进行配置,oauth2Login().tokenEndpoint()可以对令牌端点进行配置.

例子如下:

例1. 高级 OAuth2 登录配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .authorizationEndpoint(authorization -> authorization
			            ...
			    )
			    .redirectionEndpoint(redirection -> redirection
			            ...
			    )
			    .tokenEndpoint(token -> token
			            ...
			    )
			    .userInfoEndpoint(userInfo -> userInfo
			            ...
			    )
			);
	}
}
```

oauth2Login() DSL 的主要目标是与规范中定义的命名紧密结合。

OAuth 2.0 授权框架将协议端点定义如下：

授权过程使用两个授权服务器端点（HTTP 资源）：

授权端点：客户端用于通过用户代理重定向从资源所有者那里获得授权。

令牌端点：客户端用于交换访问令牌的授权许可，通常与客户端身份验证一起使用。

以及一个客户端端点：

重定向端点：授权服务器使用它通过资源所有者用户代理向客户端返回包含授权凭据的响应。

OpenID Connect Core 1.0 规范定义 UserInfo Endpoint 如下：

UserInfo 端点是一个 OAuth 2.0 受保护资源，它返回有关经过身份验证的最终用户的声明。为了获取请求的有关最终用户的声明，客户端使用通过 OpenID Connect 身份验证获取的访问令牌向 UserInfo 端点发出请求。这些声明通常由包含声明的名称-值对集合的 JSON 对象表示。

以下代码显示了可用于 oauth2Login() DSL 的完整配置选项：

示例 2. OAuth2 登录配置选项

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .clientRegistrationRepository(this.clientRegistrationRepository())
			    .authorizedClientRepository(this.authorizedClientRepository())
			    .authorizedClientService(this.authorizedClientService())
			    .loginPage("/login")
			    .authorizationEndpoint(authorization -> authorization
			        .baseUri(this.authorizationRequestBaseUri())
			        .authorizationRequestRepository(this.authorizationRequestRepository())
			        .authorizationRequestResolver(this.authorizationRequestResolver())
			    )
			    .redirectionEndpoint(redirection -> redirection
			        .baseUri(this.authorizationResponseBaseUri())
			    )
			    .tokenEndpoint(token -> token
			        .accessTokenResponseClient(this.accessTokenResponseClient())
			    )
			    .userInfoEndpoint(userInfo -> userInfo
			        .userAuthoritiesMapper(this.userAuthoritiesMapper())
			        .userService(this.oauth2UserService())
			        .oidcUserService(this.oidcUserService())
			    )
			);
	}
}
```

除了 oauth2Login() DSL，还支持 XML 配置。

以下代码显示了安全命名空间中可用的完整配置选项：

示例 3. OAuth2 登录 XML 配置选项

```xml
<http>
	<oauth2-login client-registration-repository-ref="clientRegistrationRepository"
				  authorized-client-repository-ref="authorizedClientRepository"
				  authorized-client-service-ref="authorizedClientService"
				  authorization-request-repository-ref="authorizationRequestRepository"
				  authorization-request-resolver-ref="authorizationRequestResolver"
				  access-token-response-client-ref="accessTokenResponseClient"
				  user-authorities-mapper-ref="userAuthoritiesMapper"
				  user-service-ref="oauth2UserService"
				  oidc-user-service-ref="oidcUserService"
				  login-processing-url="/login/oauth2/code/*"
				  login-page="/login"
				  authentication-success-handler-ref="authenticationSuccessHandler"
				  authentication-failure-handler-ref="authenticationFailureHandler"
				  jwt-decoder-factory-ref="jwtDecoderFactory"/>
</http>
```

#### OAuth 2.0 登录页面

默认情况下，OAuth 2.0 登录页面由 DefaultLoginPageGeneratingFilter 自动生成。默认登录页面显示每个配置的 OAuth 客户端及其 ClientRegistration.clientName 作为链接，它能够启动授权请求（或 OAuth 2.0 登录）。

为了让 DefaultLoginPageGeneratingFilter 显示配置的 OAuth 客户端的链接，注册的 ClientRegistrationRepository 还需要实现 Iterable<ClientRegistration>。请参阅 InMemoryClientRegistrationRepository 以供参考。
每个 OAuth 客户端的链接目标默认如下：

OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}"

以下行显示了一个示例：

```html
<a href="/oauth2/authorization/google">Google</>
```

要覆盖默认登录页面，请配置 oauth2Login().loginPage() 和（可选）oauth2Login().authorizationEndpoint().baseUri()。

以下清单显示了一个示例：

示例 4. OAuth2 登录页面配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .loginPage("/login/oauth2")
			    ...
			    .authorizationEndpoint(authorization -> authorization
			        .baseUri("/login/oauth2/authorization")
			        ...
			    )
			);
	}
}
```

您需要为@Controller 提供能够呈现自定义登录页面的@RequestMapping("/login/oauth2")。

如前所述，配置 oauth2Login().authorizationEndpoint().baseUri() 是可选的。但是，如果您选择对其进行自定义，请确保每个 OAuth 客户端的链接与 authorizationEndpoint().baseUri() 匹配。

以下行显示了一个示例：

```
<a href="/login/oauth2/authorization/google">Google</a>
```

#### 重定向端点

重定向端点由授权服务器用于通过资源所有者用户代理将授权响应（包含授权凭证）返回给客户端。

OAuth 2.0 登录利用了授权代码授权。因此，授权凭证就是授权码。
默认的授权响应 baseUri（重定向端点）是 /login/oauth2/code/*，它在 OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI 中定义。

如果您想自定义授权响应 baseUri，请按照以下示例进行配置：

示例 5. 重定向端点配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .redirectionEndpoint(redirection -> redirection
			        .baseUri("/login/oauth2/callback/*")
			        ...
			    )
			);
	}
}
```

您还需要确保 ClientRegistration.redirectUri 与自定义授权响应 baseUri 匹配。

以下清单显示了一个示例：

```java
return CommonOAuth2Provider.GOOGLE.getBuilder("google")
	.clientId("google-client-id")
	.clientSecret("google-client-secret")
	.redirectUri("{baseUrl}/login/oauth2/callback/{registrationId}")
	.build();
```

#### 用户信息端点

UserInfo Endpoint 包括许多配置选项，如以下小节所述：

* 映射用户权限

* OAuth 2.0 用户服务

* OpenID Connect 1.0 用户服务

#####  映射用户权限

在用户成功通过 OAuth 2.0 Provider 进行身份验证后，OAuth2User.getAuthorities()（或 OidcUser.getAuthorities()）可能会映射到一组新的 GrantedAuthority 实例，这些实例将在完成身份验证时提供给 OAuth2AuthenticationToken。

OAuth2AuthenticationToken.getAuthorities() 用于授权请求，例如在 hasRole('USER') 或 hasRole('ADMIN') 中。

映射用户权限时，有几个选项可供选择：

* 使用 GrantedAuthoritiesMapper

* OAuth2UserService 基于委托的策略

###### 使用 GrantedAuthoritiesMapper

提供 GrantedAuthoritiesMapper 的实现并按照以下示例进行配置：

示例 6. 授权权限映射器配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .userInfoEndpoint(userInfo -> userInfo
			        .userAuthoritiesMapper(this.userAuthoritiesMapper())
			        ...
			    )
			);
	}

	private GrantedAuthoritiesMapper userAuthoritiesMapper() {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach(authority -> {
				if (OidcUserAuthority.class.isInstance(authority)) {
					OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

					OidcIdToken idToken = oidcUserAuthority.getIdToken();
					OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

					// Map the claims found in idToken and/or userInfo
					// to one or more GrantedAuthority's and add it to mappedAuthorities

				} else if (OAuth2UserAuthority.class.isInstance(authority)) {
					OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;

					Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

					// Map the attributes found in userAttributes
					// to one or more GrantedAuthority's and add it to mappedAuthorities

				}
			});

			return mappedAuthorities;
		};
	}
}
```

##### OAuth2UserService 基于委托的策略

与使用 GrantedAuthoritiesMapper 相比，此策略更先进，但是，它也更灵活，因为它允许您访问 OAuth2UserRequest 和 OAuth2User（使用 OAuth 2.0 UserService 时）或 OidcUserRequest 和 OidcUser（使用 OpenID Connect 1.0 UserService 时）。

OAuth2UserRequest（和 OidcUserRequest）为您提供对关联 OAuth2AccessToken 的访问，这在委托人需要从受保护资源获取权限信息然后才能为用户映射自定义权限的情况下非常有用。

以下示例显示如何使用 OpenID Connect 1.0 UserService 实施和配置基于委托的策略：

示例 8. OAuth2UserService 配置

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
			    .userInfoEndpoint(userInfo -> userInfo
			        .oidcUserService(this.oidcUserService())
			        ...
			    )
			);
	}

	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return (userRequest) -> {
			// Delegate to the default implementation for loading a user
			OidcUser oidcUser = delegate.loadUser(userRequest);

			OAuth2AccessToken accessToken = userRequest.getAccessToken();
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			// TODO
			// 1) Fetch the authority information from the protected resource using accessToken
			// 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

			// 3) Create a copy of oidcUser but use the mappedAuthorities instead
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

			return oidcUser;
		};
	}
}
```

##### OpenID Connect 1.0 用户服务

OidcUserService 是支持 OpenID Connect 1.0 Provider 的 OAuth2UserService 的实现。

OidcUserService 在 UserInfo 端点请求用户属性时利用 DefaultOAuth2UserService。

如果您需要自定义 UserInfo 请求的预处理和/或 UserInfo 响应的后处理，则需要为 OidcUserService.setOauth2UserService() 提供自定义配置的 DefaultOAuth2UserService。

无论您是自定义 OidcUserService 还是为 OpenID Connect 1.0 提供者提供您自己的 OAuth2UserService 实现，您都需要按照以下示例进行配置：

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
				    .oidcUserService(this.oidcUserService())
				    ...
			    )
			);
	}

	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		...
	}
}
```



#### ID TOKEN 签名认证

OpenID Connect 1.0 身份验证引入了 ID 令牌，它是一种安全令牌，其中包含有关客户端使用时授权服务器对最终用户进行身份验证的声明。

ID 令牌表示为 JSON Web 令牌 (JWT)，并且必须使用 JSON Web 签名 (JWS) 进行签名。

OidcIdTokenDecoderFactory 提供了一个用于 OidcIdToken 签名验证的 JwtDecoder。默认算法为 RS256，但在客户端注册期间分配时可能会有所不同。对于这些情况，解析器可以配置为返回为特定客户端分配的预期 JWS 算法。

JWS 算法解析器是一个函数，它接受 ClientRegistration 并为客户端返回预期的 JwsAlgorithm，例如。 SignatureAlgorithm.RS256 或 MacAlgorithm.HS256

以下代码显示了如何将 OidcIdTokenDecoderFactory @Bean 配置为所有 ClientRegistration 的默认为 MacAlgorithm.HS256：

```java
@Bean
public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
	OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
	idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
	return idTokenDecoderFactory;
}
```

对于 HS256、HS384 或 HS512 等基于 MAC 的算法，与 client-id 对应的 client-secret 用作签名验证的对称密钥。
如果为 OpenID Connect 1.0 身份验证配置了多个 ClientRegistration，则 JWS 算法解析器可以评估提供的 ClientRegistration 以确定要返回的算法。

#### OpenID Connect 1.0 登出

OpenID Connect 会话管理 1.0 允许使用客户端在提供商处注销最终用户。可用的策略之一是 RP-Initiated Logout。

如果 OpenID 提供者同时支持会话管理和发现，则客户端可以从 OpenID 提供者的发现元数据中获取 end_session_endpoint URL。这可以通过使用 issuer-uri 配置 ClientRegistration 来实现，如下例所示：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-secret: okta-client-secret
            ...
        provider:
          okta:
            issuer-uri: https://dev-1234.oktapreview.com
```

… 以及实现 RP-Initiated Logout 的 OidcClientInitiatedLogoutSuccessHandler 可以配置如下：

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login(withDefaults())
			.logout(logout -> logout
				.logoutSuccessHandler(oidcLogoutSuccessHandler())
			);
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);

		// Sets the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

		return oidcLogoutSuccessHandler;
	}
}
```

OidcClientInitiatedLogoutSuccessHandler 支持 {baseUrl} 占位符。如果使用，应用程序的基本 URL，如 https://app.example.org，将在请求时替换它。

## OAuth2 客户端

OAuth 2.0客户端特性提供对[OAuth 2.0 授权框架](https://tools.ietf.org/html/rfc6749#section-1.1)所定义的客户端角色的支持.

从高层次看,核心特性如下:

授权支持

* [授权码](https://tools.ietf.org/html/rfc6749#section-1.3.1)
* [刷新令牌](https://tools.ietf.org/html/rfc6749#section-6)
* [客户端凭证](https://tools.ietf.org/html/rfc6749#section-1.3.4)
* [资源所有者密码凭证](https://tools.ietf.org/html/rfc6749#section-1.3.3)
* [JWT Bearer](https://datatracker.ietf.org/doc/html/rfc7523#section-2.1)

客户端认证支持

* [JWT Bearer]([JWT Bearer](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2))

HTTP 客户端支持

* [Servlet环境下的 webClient集成](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorized-clients.html#oauth2Client-webclient-servlet)(用于请求被保护的资源)

HTTPSecurity.oauth2Client() DSL 提供了一些 OAuth2.0 客户端所使用的核心组件的配置项.

此外,HttpSecurity.oauth2Client().authorizationCodeGrant()使得授权码认证自定义成为可能.

以下的代码展示了HttpSecurity.oauth2Client() DSL提供的完整配置项

例1. OAuth2 客户端配置项

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Client(oauth2 -> oauth2
				.clientRegistrationRepository(this.clientRegistrationRepository())
				.authorizedClientRepository(this.authorizedClientRepository())
				.authorizedClientService(this.authorizedClientService())
				.authorizationCodeGrant(codeGrant -> codeGrant
					.authorizationRequestRepository(this.authorizationRequestRepository())
					.authorizationRequestResolver(this.authorizationRequestResolver())
					.accessTokenResponseClient(this.accessTokenResponseClient())
				)
			);
	}
}
```

除了HttpSecurity.oauth2Client() DSL,XML 配置也是支持的.

以下代码展示了security命名空间下完整的配置项:

例2. OAuth2 客户端配置项

```xml
<http>
	<oauth2-client client-registration-repository-ref="clientRegistrationRepository"
				   authorized-client-repository-ref="authorizedClientRepository"
				   authorized-client-service-ref="authorizedClientService">
		<authorization-code-grant
				authorization-request-repository-ref="authorizationRequestRepository"
				authorization-request-resolver-ref="authorizationRequestResolver"
				access-token-response-client-ref="accessTokenResponseClient"/>
	</oauth2-client>
</http>
```

OAuth2AuthorizedClientManager负责管理OAuth 2.0客户端的授权(再授权),是可以与一个或多个

OAuth2AuthorizedClientProvider合作的.

以下的代码展示了如何注册一个OAuth2AuthorizedClientManager@Bean,并将一个提供`authorization_code`, `refresh_token`, `client_credentials` and `password` 授权方式的OAuth2AuthorizedClientProvider组合与之相关联.

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
		ClientRegistrationRepository clientRegistrationRepository,
		OAuth2AuthorizedClientRepository authorizedClientRepository) {

	OAuth2AuthorizedClientProvider authorizedClientProvider =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.authorizationCode()
					.refreshToken()
					.clientCredentials()
					.password()
					.build();

	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
			new DefaultOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientRepository);
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

### 核心接口和类

### OAuth2 授权方式

#### ClientRegister

#### ClientRegistrationRepository

#### OAuth2AuthorizedClient

#### OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

#### OAuth2AuthorizedClientManager / OAuth2AuthorizedClientProvider

### OAuth2 客户端认证

#### 授权码

#### 刷新令牌

#### 客户端凭证

#### 资源所有者密码凭证

#### JWT Bearer

### OAuth2 已授权客户端

## OAuth2 资源服务器

Spring Security 支持使用以下两种OAuth 2.0 [Bearer 令牌](https://tools.ietf.org/html/rfc6750.html)来保护端点:

* [JWT](https://tools.ietf.org/html/rfc7519)
* 不透明令牌

这在应用把它的授权管理代理给一个授权服务的时候是比较方便的.授权服务器能被资源服务器查询来对请求进行授权.

这部分内容提供了Spring Security如何提供OAuth 2.0 Bearer 令牌支持的细节.

来看下Bearer 令牌是如何在Spring Security中运作的.首先就像Basic认证一样,[WWW-Authenticate](https://tools.ietf.org/html/rfc7235#section-4.1) 请求头会被发送回给客户端.

![bearerauthenticationentrypoint](https://docs.spring.io/spring-security/reference/_images/servlet/oauth2/bearerauthenticationentrypoint.png)



上图展示了所对应的SecurityFilterchain

## OAuth2 授权服务器





