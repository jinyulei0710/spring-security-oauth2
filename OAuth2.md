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

#### ClientRegisteration

ClientRegistration 是 OAuth 2.0 或 OpenID Connect 1.0 提供者注册的客户端的呈现。

客户端注册保存信息，例如客户端 ID、客户端机密、授权授予类型、重定向 URI、范围、授权 URI、令牌 URI 和其他详细信息。

ClientRegistration 及其属性定义如下：

```java
public final class ClientRegistration {
	private String registrationId;	
	private String clientId;	
	private String clientSecret;	
	private ClientAuthenticationMethod clientAuthenticationMethod;	
	private AuthorizationGrantType authorizationGrantType;	
	private String redirectUri;	
	private Set<String> scopes;	
	private ProviderDetails providerDetails;
	private String clientName;	

	public class ProviderDetails {
		private String authorizationUri;	
		private String tokenUri;	
		private UserInfoEndpoint userInfoEndpoint;
		private String jwkSetUri;	
		private String issuerUri;	
        private Map<String, Object> configurationMetadata;

		public class UserInfoEndpoint {
			private String uri;	
            private AuthenticationMethod authenticationMethod;
			private String userNameAttributeName;	

		}
	}
}
```

1. registrationId：唯一标识 ClientRegistration 的 ID。
2. clientId：客户端标识符。
3. clientSecret：客户端密码。
4. clientAuthenticationMethod：用于向提供者验证客户端的方法。支持的值为 client_secret_basic、client_secret_post、private_key_jwt、client_secret_jwt 和 none[（公共客户端）](https://tools.ietf.org/html/rfc6749#section-2.1)。
5. 授权类型：OAuth 2.0 授权框架定义了四种授权类型。支持的值是authorization_code、client_credentials、password，以及扩展授权类型urn:ietf:params:oauth:grant-type:jwt-bearer。
6. redirectUri：客户端注册的重定向 URI，在最终用户对客户端进行身份验证和授权访问后，授权服务器将最终用户的用户代理重定向到该 URI。
7. scopes：客户端在授权请求流程中请求的范围，例如 openid、电子邮件或配置文件。
8. clientName：用于客户端的描述性名称。该名称可用于某些场景，例如在自动生成的登录页面中显示客户端的名称时。
9. authorizationUri：授权服务器的授权端点 URI。
10. tokenUri：授权服务器的令牌端点 URI。
11. jwkSetUri：用于从授权服务器检索 JSON Web 密钥 (JWK) 集的 URI，其中包含用于验证 ID 令牌的 JSON Web 签名 (JWS) 和可选的 UserInfo 响应的加密密钥。
12. issuerUri：返回 OpenID Connect 1.0 提供者或 OAuth 2.0 授权服务器的颁发者标识符 uri。
13. configurationMetadata：OpenID 提供程序配置信息。仅当配置了 Spring Boot 2.x 属性 spring.security.oauth2.client.provider.[providerId].issuerUri 时，此信息才可用。
14. (userInfoEndpoint)uri：用于访问经过身份验证的最终用户的声明/属性的 UserInfo 端点 URI。
15. (userInfoEndpoint)authenticationMethod：向 UserInfo Endpoint 发送访问令牌时使用的身份验证方法。支持的值是标题、表单和查询。
16. userNameAttributeName：在引用最终用户的名称或标识符的 UserInfo 响应中返回的属性的名称。

ClientRegistration 可以使用 OpenID Connect Provider 的 Configuration 端点或 Authorization Server 的 Metadata 端点的发现进行初始配置。

ClientRegistrations 提供了以这种方式配置 ClientRegistration 的便捷方法，如以下示例所示：

```java
ClientRegistration clientRegistration =
    ClientRegistrations.fromIssuerLocation("https://idp.example.com/issuer").build();
```

上面的代码会依次查询https://idp.example.com/issuer/.well-known/openid-configuration，然后是https://idp.example.com/.well-known/openid-configuration/issuer ，最后是 https://idp.example.com/.well-known/oauth-authorization-server/issuer，首先停止返回 200 响应。

作为替代方案，您可以使用 ClientRegistrations.fromOidcIssuerLocation() 仅查询 OpenID Connect 提供程序的配置端点。

#### ClientRegistrationRepository

ClientRegistrationRepository 用作 OAuth 2.0 / OpenID Connect 1.0 ClientRegistration 的存储库。

客户端注册信息最终由关联的授权服务器存储和拥有。该存储库提供检索主要客户端注册信息的子集的能力，该子集与授权服务器一起存储。

Spring Boot 2.x 自动配置将 spring.security.oauth2.client.registration.[registrationId] 下的每个属性绑定到 ClientRegistration 的实例，然后在 ClientRegistrationRepository 中组合每个 ClientRegistration 实例。

ClientRegistrationRepository 的默认实现是 InMemoryClientRegistrationRepository

自动配置还将 ClientRegistrationRepository 注册为 ApplicationContext 中的 @Bean，以便在应用程序需要时可用于依赖注入。

以下清单显示了一个示例：

```java
@Controller
public class OAuth2ClientController {

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@GetMapping("/")
	public String index() {
		ClientRegistration oktaRegistration =
			this.clientRegistrationRepository.findByRegistrationId("okta");

		...

		return "index";
	}
}
```

#### OAuth2AuthorizedClient

OAuth2AuthorizedClient 是授权客户端的表示。当最终用户（资源所有者）已授予客户端访问其受保护资源的权限时，客户端被视为已获得授权。

OAuth2AuthorizedClient 用于将 OAuth2AccessToken（和可选的 OAuth2RefreshToken）与 ClientRegistration（客户端）和资源所有者相关联，后者是授予授权的主体最终用户。

#### OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

OAuth2AuthorizedClientRepository 负责在 Web 请求之间持久化 OAuth2AuthorizedClient(s)。而 OAuth2AuthorizedClientService 的主要作用是在应用程序级别管理 OAuth2AuthorizedClient(s)。

从开发人员的角度来看，OAuth2AuthorizedClientRepository 或 OAuth2AuthorizedClientService 提供了查找与客户端关联的 OAuth2AccessToken 的功能，以便它可以用于发起受保护的资源请求。

以下清单显示了一个示例：

```
@Controller
public class OAuth2ClientController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")
    public String index(Authentication authentication) {
        OAuth2AuthorizedClient authorizedClient =
            this.authorizedClientService.loadAuthorizedClient("okta", authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "index";
    }
}
```

Spring Boot 2.x 自动配置在 ApplicationContext 中注册 OAuth2AuthorizedClientRepository 和/或 OAuth2AuthorizedClientService @Bean。但是，应用程序可以选择覆盖和注册自定义 OAuth2AuthorizedClientRepository 或 OAuth2AuthorizedClientService @Bean。

OAuth2AuthorizedClientService 的默认实现是 InMemoryOAuth2AuthorizedClientService，它将 OAuth2AuthorizedClient(s) 存储在内存中。

或者，JDBC 实现 JdbcOAuth2AuthorizedClientService 可以配置为在数据库中持久化 OAuth2AuthorizedClient(s)。

JdbcOAuth2AuthorizedClientService 依赖于 OAuth 2.0 Client Schema 中描述的表定义。

#### OAuth2AuthorizedClientManager / OAuth2AuthorizedClientProvider

OAuth2AuthorizedClientManager 负责 OAuth2AuthorizedClient(s) 的整体管理。

主要职责包括：

* 使用 OAuth2AuthorizedClientProvider 授权（或重新授权）OAuth 2.0 客户端。

* 委托 OAuth2AuthorizedClient 的持久性，通常使用 OAuth2AuthorizedClientService 或 OAuth2AuthorizedClientRepository。

* 当 OAuth 2.0 客户端已成功授权（或重新授权）时，委托给 OAuth2AuthorizationSuccessHandler。

* 当 OAuth 2.0 客户端无法授权（或重新授权）时委托给 OAuth2AuthorizationFailureHandler。

OAuth2AuthorizedClientProvider 实现了授权（或重新授权）OAuth 2.0 客户端的策略。实现通常会实现授权授予类型，例如。 authorization_code、client_credentials 等。

OAuth2AuthorizedClientManager 的默认实现是 DefaultOAuth2AuthorizedClientManager，它与 OAuth2AuthorizedClientProvider 相关联，该 OAuth2AuthorizedClientProvider 可以使用基于委托的组合支持多种授权授予类型。 OAuth2AuthorizedClientProviderBuilder 可用于配置和构建基于委托的组合。

以下代码显示了如何配置和构建 OAuth2AuthorizedClientProvider 组合的示例，该组合提供对 authorization_code、refresh_token、client_credentials 和密码授权授予类型的支持：

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

当授权尝试成功时，DefaultOAuth2AuthorizedClientManager 将委托给 OAuth2AuthorizationSuccessHandler，后者（默认情况下）将通过 OAuth2AuthorizedClientRepository 保存 OAuth2AuthorizedClient。在重新授权失败的情况下，例如。刷新令牌不再有效，之前保存的 OAuth2AuthorizedClient 将通过 RemoveAuthorizedClientOAuth2AuthorizationFailureHandler 从 OAuth2AuthorizedClientRepository 中删除。可以通过 setAuthorizationSuccessHandler(OAuth2AuthorizationSuccessHandler) 和 setAuthorizationFailureHandler(OAuth2AuthorizationFailureHandler) 自定义默认行为。

DefaultOAuth2AuthorizedClientManager 还与 Function<OAuth2AuthorizeRequest, Map<String, Object>> 类型的 contextAttributesMapper 相关联，它负责将属性从 OAuth2AuthorizeRequest 映射到要关联到 OAuth2AuthorizationContext 的属性映射。当您需要提供具有必需（支持）属性的 OAuth2AuthorizedClientProvider 时，这会很有用，例如。 PasswordOAuth2AuthorizedClientProvider 要求资源所有者的用户名和密码在 OAuth2AuthorizationContext.getAttributes() 中可用。

以下代码显示了 contextAttributesMapper 的示例：

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
		ClientRegistrationRepository clientRegistrationRepository,
		OAuth2AuthorizedClientRepository authorizedClientRepository) {

	OAuth2AuthorizedClientProvider authorizedClientProvider =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.password()
					.refreshToken()
					.build();

	DefaultOAuth2AuthorizedClientManager authorizedClientManager =
			new DefaultOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientRepository);
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	// Assuming the `username` and `password` are supplied as `HttpServletRequest` parameters,
	// map the `HttpServletRequest` parameters to `OAuth2AuthorizationContext.getAttributes()`
	authorizedClientManager.setContextAttributesMapper(contextAttributesMapper());

	return authorizedClientManager;
}

private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
	return authorizeRequest -> {
		Map<String, Object> contextAttributes = Collections.emptyMap();
		HttpServletRequest servletRequest = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
		String username = servletRequest.getParameter(OAuth2ParameterNames.USERNAME);
		String password = servletRequest.getParameter(OAuth2ParameterNames.PASSWORD);
		if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
			contextAttributes = new HashMap<>();

			// `PasswordOAuth2AuthorizedClientProvider` requires both attributes
			contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
			contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
		}
		return contextAttributes;
	};
}
```



DefaultOAuth2AuthorizedClientManager 旨在在 HttpServletRequest 的上下文中使用。在 HttpServletRequest 上下文之外操作时，请改用 AuthorizedClientServiceOAuth2AuthorizedClientManager。

服务应用程序是何时使用 AuthorizedClientServiceOAuth2AuthorizedClientManager 的常见用例。服务应用程序通常在后台运行，没有任何用户交互，并且通常在系统级帐户而不是用户帐户下运行。配置了 client_credentials 授权类型的 OAuth 2.0 客户端可以被视为一种服务应用程序。

以下代码显示了如何配置提供对 client_credentials 授权类型支持的 AuthorizedClientServiceOAuth2AuthorizedClientManager 的示例：

```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(
		ClientRegistrationRepository clientRegistrationRepository,
		OAuth2AuthorizedClientService authorizedClientService) {

	OAuth2AuthorizedClientProvider authorizedClientProvider =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.clientCredentials()
					.build();

	AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
			new AuthorizedClientServiceOAuth2AuthorizedClientManager(
					clientRegistrationRepository, authorizedClientService);
	authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	return authorizedClientManager;
}
```

OAuth2 授权支持

#### 授权码

请参阅 OAuth 2.0 授权框架以获取有关[授权码](https://tools.ietf.org/html/rfc6749#section-1.3.1)授权的更多详细信息。

##### 获取授权

授权码授权请参考授权[请求/响应](https://tools.ietf.org/html/rfc6749#section-4.1.1)协议流程。

##### 初始化授权请求

OAuth2AuthorizationRequestRedirectFilter 使用 OAuth2AuthorizationRequestResolver 来解析 OAuth2AuthorizationRequest 并通过将最终用户的用户代理重定向到授权服务器的授权端点来启动授权代码授权流程。

OAuth2AuthorizationRequestResolver 的主要作用是从提供的 Web 请求中解析 OAuth2AuthorizationRequest。默认实现 DefaultOAuth2AuthorizationRequestResolver 匹配（默认）路径 /oauth2/authorization/{registrationId} 提取 registrationId 并使用它为关联的 ClientRegistration 构建 OAuth2AuthorizationRequest。

鉴于 OAuth 2.0 客户端注册的以下 Spring Boot 2.x 属性：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-secret: okta-client-secret
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/authorized/okta"
            scope: read, write
        provider:
          okta:
            authorization-uri: https://dev-1234.oktapreview.com/oauth2/v1/authorize
            token-uri: https://dev-1234.oktapreview.com/oauth2/v1/token
```

基本路径为 /oauth2/authorization/okta 的请求将通过 OAuth2AuthorizationRequestRedirectFilter 发起授权请求重定向，并最终启动授权代码授权流程。

AuthorizationCodeOAuth2AuthorizedClientProvider 是授权代码授权的 OAuth2AuthorizedClientProvider 的实现，它也通过 OAuth2AuthorizationRequestRedirectFilter 启动授权请求重定向。

如果 OAuth 2.0 Client 是 Public Client，那么配置 OAuth 2.0 Client 注册如下：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            client-id: okta-client-id
            client-authentication-method: none
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/authorized/okta"
            ...
```

使用 Proof Key for Code Exchange (PKCE) 支持公共客户端。如果客户端在不受信任的环境中运行（例如本机应用程序或基于 Web 浏览器的应用程序），因此无法维护其凭据的机密性，则在以下条件为真时将自动使用 PKCE：

客户端机密被省略（或为空）

客户端身份验证方法设置为“无”（ClientAuthenticationMethod.NONE）

DefaultOAuth2AuthorizationRequestResolver 还支持使用 UriComponentsBuilder 的重定向 uri 的 URI 模板变量。

以下配置使用所有支持的 URI 模板变量：

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          okta:
            ...
            redirect-uri: "{baseScheme}://{baseHost}{basePort}{basePath}/authorized/{registrationId}"
            ...
```

{baseUrl} 解析为 {baseScheme}://{baseHost}{basePort}{basePath}

当 OAuth 2.0 客户端在代理服务器后面运行时，使用 URI 模板变量配置重定向 uri 特别有用。这确保在扩展重定向 uri 时使用 X-Forwarded-* 标头

##### 自定义授权请求

OAuth2AuthorizationRequestResolver 可以实现的主要用例之一是能够使用 OAuth 2.0 授权框架中定义的标准参数之上的附加参数自定义授权请求。

例如，OpenID Connect 为授权代码流定义了额外的 OAuth 2.0 请求参数，扩展自 OAuth 2.0 授权框架中定义的标准参数。这些扩展参数之一是提示参数。

选修的。空格分隔、区分大小写的 ASCII 字符串值列表，指定授权服务器是否提示最终用户重新进行身份验证和同意。定义的值为：none、login、consent、select_account

以下示例显示了如何使用 Consumer<OAuth2AuthorizationRequest.Builder> 配置 DefaultOAuth2AuthorizationRequestResolver，该 Consumer<OAuth2AuthorizationRequest.Builder> 为 oauth2Login() 自定义授权请求，包括请求参数 prompt=consent。

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
			.oauth2Login(oauth2 -> oauth2
				.authorizationEndpoint(authorization -> authorization
					.authorizationRequestResolver(
						authorizationRequestResolver(this.clientRegistrationRepository)
					)
				)
			);
	}

	private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
			ClientRegistrationRepository clientRegistrationRepository) {

		DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
				new DefaultOAuth2AuthorizationRequestResolver(
						clientRegistrationRepository, "/oauth2/authorization");
		authorizationRequestResolver.setAuthorizationRequestCustomizer(
				authorizationRequestCustomizer());

		return  authorizationRequestResolver;
	}

	private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
		return customizer -> customizer
					.additionalParameters(params -> params.put("prompt", "consent"));
	}
}
```

对于简单的用例，附加请求参数对于特定的提供者总是相同的，它可以直接添加到授权 uri 属性中。 例如，如果请求参数提示的值始终为提供者 okta 的同意，那么简单地配置如下：

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          okta:
            authorization-uri: https://dev-1234.oktapreview.com/oauth2/v1/authorize?prompt=consent
```

前面的示例显示了在标准参数之上添加自定义参数的常见用例。或者，如果您的要求更高级，您可以通过简单地覆盖 OAuth2AuthorizationRequest.authorizationRequestUri 属性来完全控制构建授权请求 URI。

OAuth2AuthorizationRequest.Builder.build() 构造 OAuth2AuthorizationRequest.authorizationRequestUri，它表示授权请求 URI，包括使用 application/x-www-form-urlencoded 格式的所有查询参数。

以下示例显示了来自前面示例的 authorizationRequestCustomizer() 的变体，而是覆盖了 OAuth2AuthorizationRequest.authorizationRequestUri 属性。

```java
private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
	return customizer -> customizer
				.authorizationRequestUri(uriBuilder -> uriBuilder
					.queryParam("prompt", "consent").build());
}
```

##### 存储授权请求

AuthorizationRequestRepository 负责 OAuth2AuthorizationRequest 从发起授权请求到收到授权响应（回调）的持久化。

OAuth2AuthorizationRequest 用于关联和验证授权响应。

AuthorizationRequestRepository 的默认实现是 HttpSessionOAuth2AuthorizationRequestRepository，它将 OAuth2AuthorizationRequest 存储在 HttpSession 中。

如果您有 AuthorizationRequestRepository 的自定义实现，则可以按照以下示例进行配置：

示例 1. AuthorizationRequestRepository 配置

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Client(oauth2 -> oauth2
				.authorizationCodeGrant(codeGrant -> codeGrant
					.authorizationRequestRepository(this.authorizationRequestRepository())
					...
				)
			);
	}
}
```

##### 请求访问令牌

有关授权码授予，请参阅访问[令牌请求/响应](https://tools.ietf.org/html/rfc6749#section-4.1.3)协议流程。

授权代码授权的 OAuth2AccessTokenResponseClient 的默认实现是 DefaultAuthorizationCodeTokenResponseClient，它使用 RestOperations 在授权服务器的令牌端点交换访问令牌的授权代码。

DefaultAuthorizationCodeTokenResponseClient 非常灵活，因为它允许您自定义令牌请求的预处理和/或令牌响应的后处理。

##### 自定义访问请求

如果您需要自定义令牌请求的预处理，您可以提供 DefaultAuthorizationCodeTokenResponseClient.setRequestEntityConverter() 和自定义 Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>>。默认实现 OAuth2AuthorizationCodeGrantRequestEntityConverter 构建标准 OAuth 2.0 访问令牌请求的 RequestEntity 表示。但是，提供自定义转换器将允许您扩展标准令牌请求并添加自定义参数。

要仅自定义请求的参数，您可以为 OAuth2AuthorizationCodeGrantRequestEntityConverter.setParametersConverter() 提供自定义 Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> 以完全覆盖随请求发送的参数。这通常比直接构造 RequestEntity 更简单。

如果您只想添加额外的参数，您可以为 OAuth2AuthorizationCodeGrantRequestEntityConverter.addParametersConverter() 提供一个自定义 Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> 来构造一个聚合转换器。

自定义转换器必须返回 OAuth 2.0 访问令牌请求的有效 RequestEntity 表示，该请求可由预期的 OAuth 2.0 提供者理解。

##### 自定义访问令牌响应

另一方面，如果您需要自定义令牌响应的后处理，则需要为 DefaultAuthorizationCodeTokenResponseClient.setRestOperations() 提供自定义配置的 RestOperations。默认的 RestOperations 配置如下：

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
		new FormHttpMessageConverter(),
		new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

Spring MVC FormHttpMessageConverter 是必需的，因为它在发送 OAuth 2.0 访问令牌请求时使用。
OAuth2AccessTokenResponseHttpMessageConverter 是 OAuth 2.0 访问令牌响应的 HttpMessageConverter。您可以为 OAuth2AccessTokenResponseHttpMessageConverter.setAccessTokenResponseConverter() 提供自定义 Converter<Map<String, Object>, OAuth2AccessTokenResponse>，用于将 OAuth 2.0 访问令牌响应参数转换为 OAuth2AccessTokenResponse。

OAuth2ErrorResponseErrorHandler 是一个可以处理 OAuth 2.0 错误的 ResponseErrorHandler，例如。 400 错误请求。它使用 OAuth2ErrorHttpMessageConverter 将 OAuth 2.0 错误参数转换为 OAuth2Error。

无论您是自定义 DefaultAuthorizationCodeTokenResponseClient 还是提供您自己的 OAuth2AccessTokenResponseClient 实现，您都需要按照以下示例进行配置：

示例 2. 访问令牌响应配置

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.oauth2Client(oauth2 -> oauth2
				.authorizationCodeGrant(codeGrant -> codeGrant
					.accessTokenResponseClient(this.accessTokenResponseClient())
					...
				)
			);
	}
}
```



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





