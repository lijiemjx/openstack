#keystone


##1、	什么是keystone

Keystone(OpenStack Identity Service)是OpenStack框架中的身份管理服务（Identity service），负责管理身份验证、资源服务目录、基于用户角色的访问控制和服务令牌管理功能。
Keystone的作用类似一个服务总线，Nova、Glance、Horizon、Swift、Cinder、Neutron等服务都需要通过Keystone来注册其服务的Endpoint（可理解为服务的访问点或者URL），针对这些服务的任何调用都需要经过Keystone的身份认证，并获得服务的Endpoint来进行访问。	

- 用户身份验证
    - 用户身份信息管理和存储
    - 管理用户相关的 project、role、group 和 domain等
    - 用户 credential 的存放、验证、令牌管理等

- 权限管理
    - 用户目录管理（service、endpoint）
    

##2、 keystone基本概念

用户管理：

（1）Domain域：域包含project。

（2）project（tenant）项目（租户）：一个用于分组或者隔离资源的容器。一个 project（tenant）可能对应一个客户、账号、组织或者项目。在 OpenStack 中，用户至少必须在一个project（tenant）中。project（tenant）容器的可使用资源的限制成为 project（tenant）Quota，它包括project（tenant）内各子资源的quota。

（3）User 用户：一个使用 OpenStack 云服务的人、系统或者服务的数字表示。 用户需要登录，然后被分配 token 去访问资源。用户可以被分配到一个project（tenant），并赋予不同的角色。



（4）Role 角色：Keystone 中，被访问的服务会判断访问它的用户的角色，以及每个role访问资源或者操作的权限。系统默认使用 admin 和 _member_两个角色。User 验证的时候必须带有制定的 project，roles会被分配到指定的project。

默认的角色有admin和user两种。
有domain admin和cloud admin，cloud admin是云管理员，可以对域进行管理，domain admin是域管理员，对某个域内进行管理，管理project。Project admin，对project进行管理。

（5）Group 用户组：一个用户组包含多个用户，一个用户也可以属于多个用户组，通过给用户组赋予权限，可以给用户进行批量授权。


（6）Policy 策略：OpenStack 对用户的验证除了 OpenStack 的身份验证以外，还需要鉴别用户对某个服务是否有访问权限。Policy 机制就是用来控制某一个User在某个project（Tenant）中某个操作的权限。这个 User 能执行什么操作，不能执行什么操作，就是通过 policy 机制来实现的。对于 Keystone 服务来说，policy 就是一个json 文件，默认是 /etc/keystone/policy.json。通过配置这个文件，Keystone Service 实现了对 User 的基于用户角色的权限管理。




（7） Credential 用户证据：用来证明用户身份的证据，可以是用户名和密码、用户名和API key，或者一个 Keystone 分配的身份token。

（8）Authentication 身份验证：验证用户身份的过程。Keystone 服务通过检查用户的 Credential 来确定用户的身份。最开始，使用用户名/密码或者用户名/API key作为credential。当用户的credential被验证后，Keystone 会给用户分配一个 authentication token 供该用户后续的请求使用。

（9）Token 令牌：一个用于访问 OpenStack API 和资源的字符串。一个 token 可能在任何时间被撤销（revoke），因此其有效期是有限的。OpenStack中，token 是和特定的project（tenant）是绑定的，因此如果 user 如果访问多个project（tenant）的话他就需要多个token。
还有一种unscoped token，不能访问project，只能用来获取project列表



（10）Service 服务：一个 OpenStack 服务，比如Nova、Swift或者Glance等。每个服务提供一个或者多个 endpoint 供用户访问资源以及进行操作。

（11）Endpoint 端点：一个网络可访问的服务地址，通过它你可以访问一个服务，通常是个 URL 地址。不同 region 有不同的service endpoint。endpoint告诉也可告诉 OpenStack service 去哪里访问特定的 servcie。比如，当 Nova 需要访问 Glance 服务去获取 image 时，Nova 通过访问 Keystone 拿到 Glance 的 endpoint，然后通过访问该 endpoint 去获取Glance服务。我们可以通过Endpoint的 region 属性去定义多个 region。Endpoint 该使用对象分为三类：
•	adminurl 给 admin 用户使用
•	internalurl 给 OpenStack 内部服务使用来跟别的服务通信
•	publicurl 其它用户可以访问的地址
![PNG](images/user.png)


##3、keystone组件、代码结构。

###3.1 keystone组件

Keystone分六个services：


	Identity（认证）：用户身份验证和用户与用户组的数据提供。可以由该模块提供也可以由其他后端模块提供，如LDAP。
	Resource（资源）：项目（project）和domain（域）的数据。可以由该模块提供也可以由其他后端模块提供，如LDAP。
	Assignment（角色分配）：为用户分配某一角色，来控制用户的访问权限。
	Token（令牌）管理：用户身份认证后，会提供给用户一个可以请求后续资源的令牌，token服务是用来验证并管理该令牌。
	Catalog（目录）管理：对外提供一个服务的查询目录，即每隔服务的可访问Endpoint列表。服务目录和令牌是同时返回给用户的。
	Policy（安全策略/访问控制）：一个机于规则的身份验证引擎，通过配置文件来定义各种操作与用户角色之间的匹配关系。


###3.2 keystone代码结构
![PNG](images/keystone_tree.png)


（1）etc目录下：

	default_catalog.templates :服务目录模板文件
	keystone.conf.sample:主配置文件
	keystone-paste.ini:paste deploy 配置文件
	logging.conf.sample：日志配置文件
	policy.json： 访问控制配置文件
	
   (2)cmd 目录下：

   cli.py 是个 CLI 工具，它通过和 Keystone service 交互来做一些无法使用 Keystone REST API 来进行的操作，包括：

	db_sync: Sync the database.
	db_version: Print the current migration version of the database.
	mapping_purge: Purge the identity mapping table.
	pki_setup: Initialize the certificates used to sign tokens.
	saml_idp_metadata: Generate identity provider metadata.
	ssl_setup: Generate certificates for SSL.
	token_flush: Purge expired tokens.


（3）keystone 目录下：

   每个Keystone 组件，比如 catalog， token 等都有一个单独的目录。每个组件目录中：
	
	routes.py 定义了该组件的 routes。
	controller.py 文件定义了该组件所管理的对象，比如 assignment 的controller.py 文件定义了 Tenant、Role、Project 等类。
	core.py 定了两个类 Manager 和 Driver。Manager 类对外提供该组件操作具体对象的方法入口； Driver 类定义了该组件需要其Driver实现类所提供的接口。
	backend 目录下的每个文件是每个具体driver 的实现
	contrib 目录包括resource extension 和 extension resource 的类文件。



##4、	Keystone主要工作详述

###4.1keystone安装和启动过程
4.1.1 keystone安装配置

   （1）建立数据库，用户并授权

		CREATE DATABASE keystone;
		GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY 'KEYSTONE_DBPASS';
		GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY 'KEYSTONE_DBPASS';
    
   （2）配置

		[DEFAULT]
        #配置admin token，用于引导keystone启动，配置为None就会被忽略。
		admin_token = ADMIN_TOKEN         

		[database]
        #数据库连接配置
		connection = mysql+pymysql://keystone:KEYSTONE_DBPASS@controller/keystone   

		[token]
        #token生成的方法
		provider = fernet


注：

a. 建议在生产环境中删除admin_token配置，需要删除AdminTokenAuthMiddleware配置，在keystone-paste.ini中可以配置删除pipline中的admin_token_auth即可。
b. provider生成的方法fernet|pkiz|pki|uuid。

（3）同步数据库
	su -s /bin/sh -c "keystone-manage db_sync" keystone
	
（4）配置Apache服务器

	Listen 5000
	Listen 35357

	<VirtualHost *:5000>
	    WSGIDaemonProcess keystone-public processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
	    WSGIProcessGroup keystone-public
	    WSGIScriptAlias / /usr/bin/keystone-wsgi-public
	    WSGIApplicationGroup %{GLOBAL}
	    WSGIPassAuthorization On
	    ErrorLogFormat "%{cu}t %M"
	    ErrorLog /var/log/httpd/keystone-error.log
	    CustomLog /var/log/httpd/keystone-access.log combined
	
	    <Directory /usr/bin>
	        Require all granted
	    </Directory>
	</VirtualHost>

	<VirtualHost *:35357>
	    WSGIDaemonProcess keystone-admin processes=5 threads=1 user=keystone group=keystone display-name=%{GROUP}
	    WSGIProcessGroup keystone-admin
	    WSGIScriptAlias / /usr/bin/keystone-wsgi-admin
	    WSGIApplicationGroup %{GLOBAL}
	    WSGIPassAuthorization On
	    ErrorLogFormat "%{cu}t %M"
	    ErrorLog /var/log/httpd/keystone-error.log
	    CustomLog /var/log/httpd/keystone-access.log combined
	
	    <Directory /usr/bin>
	        Require all granted
	    </Directory>
	</VirtualHost>	

（5）启动服务器

	systemctl enable httpd.service
	systemctl start httpd.service
	也可以通过keystone-all命令启动。

4.1.2 keystone启动过程

/usr/bin/keystone-all 会启动 keystone 的两个service：admin and main，它们分别对应 /etc/keystone/keystone-paste.ini 文件中的两个composite：

	[composite:main]
	use = egg:Paste#urlmap
	/v2.0 = public_api
	/v3 = api_v3
	/ = public_version_api
	
	[composite:admin]
	use = egg:Paste#urlmap
	/v2.0 = admin_api
	/v3 = api_v3
	/ = admin_version_api

可见 admin service 提供给administrator 使用；main 提供给 public 使用。它们分别都有 V2.0 和 V3 版本。比较下 admin 和 public：

<table border="0">
<tbody>
<tr>
<td><strong>名称</strong></td>
<td><strong>middlewares</strong></td>
<td><strong>factory</strong></td>
<td><strong>功能区别</strong></td>
</tr>
<tr>
<td>admin</td>
<td>比 public 多&nbsp;s3_extension</td>
<td>keystone.service:admin_app_factory</td>
<td rowspan="2">
<p>从 factory 函数来看， admin service 比 public service 多了&nbsp;identity 管理功能， 以及 assignment 的admin/public 区别：</p>
<p>1. admin 多了对 GET&nbsp;/users/{user_id} 的支持，多了&nbsp;get_all_projects，&nbsp;get_project，get_user_roles 等功能</p>
<p>2. keystone 对 admin service 提供 admin extensions, 比如 <a href="http://docs.rackspace.com/openstack-extensions/auth/OS-KSADM-admin-devguide/content/Admin_API_Service_Developer_Operations-d1e1357.html" target="_blank">OS-KSADM</a>&nbsp;等；对 public service 提供 public extensions。</p>
<p><strong>简单总结一下， public service 主要提供了身份验证和目录服务功能；admin service 增加了 tenant、user、role、user group 的管理功能。</strong></p>
</td>
</tr>
<tr>
<td>public</td>
<td>
<p>sizelimit url_normalize build_auth_context token_auth admin_token_auth xml_body_v2</p>
<p>json_body ec2_extension user_crud_extension</p>
</td>
<td>keystone.service:public_app_factory</td>
</tr>
</tbody>
</table>

 

/usr/bin/keystone-all 会启动 admin 和 public 两个 service，分别绑定不同 host 和 端口。默认的话，绑定host 都是 0.0.0.0； admin 的绑定端口是 35357 （admin_port）， public 的绑定端口是 5000 （public_port）。因此，给 admin 使用的 OS_AUTH_URL 为 http://controller:35357/v3， 给 public 使用的 OS_AUTH_URL=http://controller:5000/v3.


###4.2 Keystone与其他模块之间的关联配置

    [keystone_authtoken]
		auth_uri = http://controller:5000
		auth_url = http://controller:35357
		auth_plugin = password
		project_domain_id = default
		user_domain_id = default
		project_name = service
		username = glance
		password = GLANCE_PASS
        memcache_servers = 127.0.0.1:11211
	[paste_deploy]
		flavor = keystone
	
###4.3 用户的username/password身份验证和token生成
4.3.1 用户身份认证
      
   分两种情况:（1）username+password
                 (2) token

![PNG](images/identity.png)

4.3.2 token的生成

	（1）token具有时效性，因此较为安全，对应的是project。
    （2）生成时间： 登陆时、切换project时
    （3）类型：unscoped token, scoped token
	（4）生成方式：
	token_id 是调用相应的 token provider 的 _get_token_id 方法生成的：

	UUID：uuid.uuid4().hex
	PKI：token_id = str(cms.cms_sign_token(jsonutils.dumps(token_data), CONF.signing.certfile,CONF.signing.keyfile))
	PKIZ：token_id = str(cms.pkiz_sign(jsonutils.dumps(token_data),CONF.signing.certfile,CONF.signing.keyfile))
	从中可见：

	UUDI 的 token id 只是一个纯粹的32位十六进制字符串
	PKI （Public Key Infrastructure） 的 token id 是使用 cert file 和 key file 对 token data 加密的结果
	PKIZ 的 token id 是使用 pkiz_sign 函数，使用 cert file 和 key file 对 token data 加密的结果。从下面的 code 可以看出，pkiz 生成的 token id 其实就是使用 zlib 对 PKI 生成的 token id 进行压缩，然后加上 PKIZ_ 前缀而已。其原因应该是 PKI 的 token id 太长了。供结果估计，PKIZ 能压缩 PKI 一半左右，感觉这压缩率也不高。

uuid方式：

![PNG](images/UUID-token-validation-flow-3.png)


PKI方式:

![PNG](images/PKI-token-validation-flow-1.png)

比较各种方式的优缺点：

<table border="1" cellspacing="1" cellpadding="1" align="center">
<tbody>
<tr>
<td>
<h3><span >Provider</span></h3>
</td>
<td>
<h3><span >生成方式</span></h3>
</td>
<td>长度</td><td>加密方式</td>
<td>
<h3><span >优点</span></h3>
</td>
<td>
<h3><span>缺点</span></h3>
</td>
</tr>
<tr>
<td>UUID</td>
<td>
uuid.uuid4().hex没有加密方式。
</td>
<td>32字符</td><td>未加密</td>
<td>生成的Token，长度较短，使用方便。url使用方便，回收的方式，就是从后端删除即可，实现逻辑较为清晰。</td>
<td>需要持久化后端存储，每次访问需要keystone相关服务进行认证。</td>
</tr>
<tr>
<td>PKI</td>
<td>cms_sign_data（），使用base64 encoded进行编码（替换不安全的字符），。</td>
<td>粗略统计过长度4602字符，使用</td><td>Cryptographic Message Syntax (CMS)进行加密（默认的方式sha256）</td>
<td>使用证书及私钥生成，可以线下验证（不需要走keystone认证服务），</td>
<td>长度负载重，不推荐用于生产部署<span style="color:rgb(62,67,73); font-family:Arial,sans-serif; font-size:14px; line-height:21.599998474121094px">&nbsp;：</span><tt class="docutils literal" style="color:rgb(34,34,34); font-size:1.1em; line-height:21.599998474121094px; background-color:rgb(236,240,243)"><span class="pre">keystone-manage</span>&nbsp;<span class="pre">pki_setup</span></tt><span style="color:rgb(62,67,73); font-family:Arial,sans-serif; font-size:14px; line-height:21.599998474121094px">&nbsp;</span>，需要使用由一个受信任的CA颁发的证书</td>
</tr>
<tr>
<td>PKIZ</td>
<td>同PKI，使用base64url encoding进行编码，在此基础上，使用压缩机制，长度上减小了一半，并且Token使用PKIZ_开头。</td>
<td>2301字符</td><td>Cryptographic Message Syntax (CMS)进行加密（默认的方式sha256）</td>
<td>较PKI长度上缩小了很多，</td>
<td>长度负载较重，同上PKI</td>
</tr>
<tr>
<td>Fernet</td>
<td>MessagePacked负载数据，并使用crypto.encrypt(payload)加密。</td>
<td>粗略统计长度183字符</td><td>使用对称加密</td>
<td>设计的逻辑，引入序列化，负载&#26684;式加以控制，基于此进行加密，长度比PKI（Z）要短。</td>
<td>对称加密算法，安全性低</td>
</tr>
</tbody>
</table>

（5）配置

	[token]
	#token持久存储
	driver = keystone.token.backends.sql.Token
	#token有效期
	expiration = 86400

 (6) 存储

 	a.  kvs
		key-value-store，和memcache类似，存储于内存中，每隔一段时间会追加写入文件，在keystone中，在生产环境中使用memcache和sql来代替。

    b.  memcache
		memcache 将token存放到memcache中，token本身创建之后不会被修改，只会被读，所以很适合放到cache中，加速访问，放到cache中也不需要写脚本定期清理数据库中的过期token。

		通过keystoneclient middleware filter来实现，该中间件安装在每个node上

		通过如下配置来实现

		编辑/etc/keystone/keystone.conf的Token字段：
		[token]
		caching = true
		provider = keystone.token.providers.uuid.Provider
		driver = keystone.token.persistence.backends.memcache.Token

		在节点上配置：
		[keystone_authtoken]
		auth_uri = http://keystone_server:5000/
		auth_host = keystone_server
		auth_port = 35357
		auth_protocol = http
		admin_tenant_name = service
		admin_user = nova
		admin_password = password
		memcache_servers = 127.0.0.1:11211
		token_cache_time = 3600 ＃token本地缓存的失效时间设置为1个小时。
		cache = true

    c. 	memcache_pool
		memcache_pool 在memcache的基础上，实现了memcache的连接池，可以在线程之间复用连接。
		memcache driver的缺点在于，memcache本身是分布式的设计，但是并不是高可用的，如果controller-1上的的cache服务被重启，这个节点上的所有token都会丢失掉，会带来一些错误。
		比这更困难的是，如果controller1网络不可达或者宕机，那么我们会观察到几乎每个openstack api请求都会有3s以上的卡顿。这是因为openstack默认使用python-memcached访问memcache，它提供的操作keystone的client继承自Thread.local类，和构建它的线程绑定。openstack服务启动后，会启动一定数量的子进程，每个http request到达，会有一个子进程接收，孵化一个线程去处理这个请求。如果用到memcache，线程会调用python-memcached 构建一个client类，通过这个client的实例对memcache进行操作。如果访问到网络不可达的memcache节点，卡住，操作超时，将这个节点标识为30秒内不可用，在这个线程内，不会再因此而卡住，但是这个http请求结束之后，下一个http请求过来，重新孵化的线程会reinit这个client，新的client丢失了旧的client的状态，还是可能会访问到卡住的memcache节点上。
		社区之所以要做memcache_pool，就是为了解决这个问题，将client统一由pool管理起来，memcache节点的状态，也由pool管理起来，这样每个子进程里只会卡第一次，所以强烈推荐使用memcache_pool驱动而不是memcache。社区将memcache_pool的代码从keystone复制到oslo_cache项目中，希望所有使用memcache的项目都通过它的memcachepool去访问，避免这个问题。其中，nova在M版本支持，heat在L版本支持。

	d. 	sql
		sql将token存放在数据库中，使用这种方法需要定期清理过期token，防止token表太大影响性能。
		
###4.4 权限控制机制RBAC

4.4.1 RBAC

一个用户可以在不同的租户中被分配不同的角色，一个用户也可以在同一个租户中分配多个角色。

　　/etc/[服务名称]/policy.json控制着哪些用户可以拥有什么样的服务，如：/etc/nova/policy.json定义了Compute服务的访问策略，/etc/glance/policy.json定义Image服务的访问策略，以及/etc/keystone/policy.json定义Identity服务的访问策略。 

　　实例：

　　在/etc/nova/policy.json中的配置设定卷创建的操作对用户无任何限制，在租户中的用户拥有的任何角色均可以创建卷：
　　　　　"volume:create": [],                                            

　　如果你需要仅拥有compute-user角色的用户才可以创建卷，你就需要添加一行”role:compute-user”，具体配置如下： 
　　　　　"volume:create": ["role:compute-user"]。

4.4.2 实现

Keystone 在每个子模块的 controller.py 文件中的各个控制类的方法上实施 RBAC。有几种方法，比如：

@controller.protected()
def create_region(self, context, region)

@controller.filterprotected('type', 'name')
def list_services(self, context, filters)

或者直接在函数体中使用 self.assert_admin(context)：

def get_services(self, context):
    self.assert_admin(context)
    service_list = self.catalog_api.list_services()
    return {'OS-KSADM:services': service_list}

其中，protected 和 filterprotected 在 /keystone/common/controller.py 中实现。

protected/filterprotected 最终会调用 /keystone/openstack/common/policy.py 中的 enforce 方法，具体见 2.3.2 （2）中的描述。keystone 与 openstack 其它component 中的 RBAC 实现的不同之处在于 keystone 中有时候需要做 token 验证再做 policy 检查。

4.4.3 新增role

	（1）在horizon或者命令行新建role
	（2）在policy中添加该role
	（3）为用户分配该role
	例如：如果希望一个用户只拥有管理镜像的权限，可以etc/glance/policy.json中，加入该角色，不在其他的etc/*/policy.json中增加该角色，并把之前默认的开放给所有用户的权限限制给已有的用户。
	
	
##5、	Keystone的实际应用

###5.1 identity service && policy provider

	keystone实现用户身份验证和权限控制两个功能。
	
##5.2 policy provider

keystone只提供权限控制，身份验证的功能通过其他身份验证系统来实现。

	LDAP管理 Idenity (users, groups, and group memberships)
	Keystone采用SQL管理Assignment (roles, tenants, domains).
  
   ![PNG](images/out_identity.png)

   	  1)、用户在openatck控制台的登录页面中输入用户名、口令等，提交到公司认证系统进行登录认证。
 
      2)、公司认证系统认证通过后，返回访问凭证（通常是访问token）、用户名。
 
      3)、openstack控制台通过http协议将第二步收到的访问token和用户名通过keystone提供的认证接口发给keystone，发送的http请求大致如下：
        POST http://172.19.106.242:5000/v2.0/tokens
        REMOTE_USER:  用户名
        EXTERNAL_ACCESS_TOKEN: 访问token
        Accept: application/json
        Content-Type: application/json
       
        {"auth" : { } }    
 
        REMOTE_USER头是keystone进行外部认证必须要有的，请求中存在该头keystone才会执行外部认证，其值为用户名；EXTERNAL_ACCESS_TOKEN头是自定义的，其值是公司认证系统返回的访问token。
        http body是json格式，只有auth属性，内容为空。其他的如口令等都不需要。
 
     4)、keystone收到该请求后，识别出认证请求中存在REMOTE_USER头，就进行外部认证的处理，主要是根据REMOTE_USER头中的用户名查询keystone的user表，看用户记录是否存在（所以需要将公司用户信息同步到keystone的user表中，不需同步密码字段），存在就通过了keystone的认证，后续处理流程和进行用户名/密码验证的相同，主要是颁发keystone的unscoped token等（该token不和具体的project/tenant绑定）。
        基于安全的原因，keystone会到公司认证系统验证访问token（EXTERNAL_ACCESS_TOKEN头中携带），确保该token是公司认证系统颁发，且没过期。
         该验证也可采用其他方式，如keystone回调openstack控制台来验证该访问token，或openstack控制台和keystone之间采用对称或非对称密钥，keystone对opentack传过来的签名进行验证（该签名放在另一个http头中，去掉EXTERNAL_ACCESS_TOKEN头）。外加iptables进行控制台ip地址限制。
    5)、返回keystone unscoped token给控制台。


##背景知识：
-  Restful && Endpoint
   Restful: Representational State Transfer，
   Endpoint:
-  WSGI
-  Oslo
   openstack 的通用库，可以像使用第三方库一样直接import使用
   主要包含以下几个模块：
   oslo.config：用于解析命令行和配置文件中的配置项。




##附录：

-  paste deployment http://pythonpaste.org/deploy/

-  UUID、PKI对比：https://www.mirantis.com/blog/understanding-openstack-authentication-keystone-pki/