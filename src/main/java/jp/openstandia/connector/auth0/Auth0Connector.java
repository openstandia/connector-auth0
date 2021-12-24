/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jp.openstandia.connector.auth0;

import com.auth0.client.HttpOptions;
import com.auth0.client.ProxyOptions;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.exception.RateLimitException;
import com.auth0.json.mgmt.users.UsersPage;
import com.auth0.net.Request;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.InstanceNameAware;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ResourceNotFoundException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static jp.openstandia.connector.auth0.Auth0RoleHandler.GROUP_OBJECT_CLASS;
import static jp.openstandia.connector.auth0.Auth0UserHandler.USER_OBJECT_CLASS;

@ConnectorClass(configurationClass = Auth0Configuration.class, displayNameKey = "NRI OpenStandia Amazon Cognito User Pool Connector")
public class Auth0Connector implements PoolableConnector, CreateOp, UpdateDeltaOp, DeleteOp, SchemaOp, TestOp, SearchOp<Auth0Filter>, InstanceNameAware {

    private static final Log LOG = Log.getLog(Auth0Connector.class);

    protected Auth0Configuration configuration;
    protected CognitoIdentityProviderClient client;
    protected ManagementAPI client2;

    private Map<String, AttributeInfo> userSchemaMap;
    private String instanceName;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        this.configuration = (Auth0Configuration) configuration;

        try {
            authenticateResource();
        } catch (RuntimeException e) {
            throw processException(e);
        }

        LOG.ok("Connector {0} successfully initialized", getClass().getName());
    }

    protected void authenticateResource() {
        HttpOptions httpOptions = new HttpOptions();

        if (configuration.getConnectionTimeoutInSeconds() != null) {
            httpOptions.setConnectTimeout(configuration.getConnectionTimeoutInSeconds());
        }
        if (configuration.getReadTimeoutInSeconds() != null) {
            httpOptions.setReadTimeout(configuration.getReadTimeoutInSeconds());
        }
        if (configuration.getMaxRetries() != null) {
            httpOptions.setManagementAPIMaxRetries(configuration.getMaxRetries());
        }

        // HTTP Proxy
        if (StringUtil.isNotEmpty(configuration.getHttpProxyHost())) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(configuration.getHttpProxyHost(), configuration.getHttpProxyPort()));
            ProxyOptions proxyOptions = new ProxyOptions(proxy);
            httpOptions.setProxyOptions(proxyOptions);
        }

        // Setup client
        if (configuration.getAPIToken() != null) {
            configuration.getAPIToken().access(c -> {
                configuration.getAPIToken().access(s -> {
                    client2 = new ManagementAPI(configuration.getDomain(), String.valueOf(s), httpOptions);
                });
            });
        }

        // Verify we can access the API
        checkClient();
    }

    private void checkClient() {
        if (client2 == null) {
            throw new ConfigurationException("Not initialized the API client");
        }
        UserFilter filter = new UserFilter()
                .withPage(0, 1);
        Request<UsersPage> request = client2.users().list(filter);

        try {
            UsersPage response = request.execute();
        } catch (Auth0Exception e) {
            throw processException(e);
        }
    }

    @Override
    public Schema schema() {
        try {
            SchemaBuilder schemaBuilder = new SchemaBuilder(Auth0Connector.class);

            ObjectClassInfo userSchemaInfo = Auth0UserHandler.getUserSchema(configuration);
            schemaBuilder.defineObjectClass(userSchemaInfo);

            ObjectClassInfo groupSchemaInfo = Auth0RoleHandler.getGroupSchema(configuration);
            schemaBuilder.defineObjectClass(groupSchemaInfo);

            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class);

            userSchemaMap = new HashMap<>();
            userSchemaInfo.getAttributeInfo().stream()
                    .forEach(a -> userSchemaMap.put(a.getName(), a));
            userSchemaMap = Collections.unmodifiableMap(userSchemaMap);

            return schemaBuilder.build();

        } catch (RuntimeException e) {
            throw processException(e);
        }
    }

    private Map<String, AttributeInfo> getUserSchemaMap() {
        // Load schema map if it's not loaded yet
        if (userSchemaMap == null) {
            schema();
        }
        return userSchemaMap;
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass value not provided");
        }
        LOG.info("CREATE METHOD OBJECTCLASS VALUE: {0}", objectClass);

        if (createAttributes == null) {
            throw new InvalidAttributeValueException("Attributes not provided or empty");
        }

        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler usersHandler = new Auth0UserHandler(configuration, client2, getUserSchemaMap());
                return usersHandler.createUser(createAttributes);

            } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                return groupsHandler.createRole(createAttributes);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (RuntimeException e) {
            throw processException(e);
        }
    }

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler usersHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                return usersHandler.updateDelta(uid, modifications, options);

            } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                return groupsHandler.updateDelta(uid, modifications, options);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (RuntimeException e) {
            throw processException(e);
        }
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler usersHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                usersHandler.deleteUser(uid, options);

            } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                groupsHandler.deleteGroup(objectClass, uid, options);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (RuntimeException e) {
            throw processException(e);
        }
    }

    @Override
    public FilterTranslator<Auth0Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new Auth0FilterTranslator(objectClass, options);
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) {
        if (objectClass.equals(USER_OBJECT_CLASS)) {
            try {
                Auth0UserHandler usersHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                usersHandler.getUsers(filter, resultsHandler, options);
            } catch (UserNotFoundException e) {
                // Don't throw UnknownUidException
                return;
            } catch (RuntimeException e) {
                throw processException(e);
            }

        } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
            try {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                groupsHandler.getGroups(filter, resultsHandler, options);
            } catch (ResourceNotFoundException e) {
                // Don't throw UnknownUidException
                return;
            } catch (RuntimeException e) {
                throw processException(e);
            }

        } else {
            throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
        }
    }

    @Override
    public void test() {
        try {
            dispose();
            authenticateResource();
        } catch (RuntimeException e) {
            throw processException(e);
        }
    }

    @Override
    public void dispose() {
        client.close();
        this.client = null;
        this.client2 = null;
    }

    @Override
    public void checkAlive() {
        // Do nothing
    }

    @Override
    public void setInstanceName(String instanceName) {
        this.instanceName = instanceName;
    }

    protected ConnectorException processException(Exception e) {
        if (e instanceof RuntimeException) {
            return processException((RuntimeException) e);
        }
        if (e instanceof Auth0Exception) {
            return processException((Auth0Exception) e);
        }
        return new ConnectorException(e);
    }

    protected ConnectorException processException(RuntimeException e) {
        if (e instanceof ConnectorException) {
            return (ConnectorException) e;
        }
        return new ConnectorException(e);
    }

    private ConnectorException processException(Auth0Exception e) {
        if (e instanceof RateLimitException) {
            return RetryableException.wrap(e.getMessage(), e);
        }
        if (e instanceof APIException) {
            APIException ae = (APIException) e;

            int statusCode = ae.getStatusCode();

            switch (statusCode) {
                case 400:
                    return new InvalidAttributeValueException(e);
                case 401:
                case 403:
                    return new ConnectionFailedException(e);
                case 404:
                    return new UnknownUidException(e);
                case 409:
                    return new AlreadyExistsException(e);
                case 429:
                    return RetryableException.wrap(e.getMessage(), e);
            }

            if (ae.isAccessDenied()) {
                throw new ConnectorSecurityException(ae);
            }
            if (ae.getError().equals("invalid_query_string")) {
                return new InvalidAttributeValueException(e);
            }
        }

        throw new ConnectorIOException(e);
    }
}
