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

import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.exception.RateLimitException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.InstanceNameAware;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static jp.openstandia.connector.auth0.Auth0OrganizationHandler.ORGANIZATION_OBJECT_CLASS;
import static jp.openstandia.connector.auth0.Auth0RoleHandler.ROLE_OBJECT_CLASS;
import static jp.openstandia.connector.auth0.Auth0UserHandler.USER_OBJECT_CLASS;

@ConnectorClass(configurationClass = Auth0Configuration.class, displayNameKey = "Auth0 Connector")
public class Auth0Connector implements PoolableConnector, CreateOp, UpdateDeltaOp, DeleteOp, SchemaOp, TestOp, SearchOp<Auth0Filter>, InstanceNameAware {

    private static final Log LOG = Log.getLog(Auth0Connector.class);

    protected Auth0Configuration configuration;
    protected Auth0Client client;

    private Map<String, AttributeInfo> userSchemaMap;
    private Map<String, AttributeInfo> roleSchemaMap;
    private Map<String, AttributeInfo> organizationSchemaMap;

    private String instanceName;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        this.configuration = (Auth0Configuration) configuration;
        initClient();
        LOG.ok("Connector {0} successfully initialized", getClass().getName());
    }

    protected void initClient() {
        this.client = new Auth0Client();
        try {
            client.initClient(configuration);
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public Schema schema() {
        try {
            SchemaBuilder schemaBuilder = new SchemaBuilder(Auth0Connector.class);

            ObjectClassInfo userSchemaInfo = Auth0UserHandler.getSchema(configuration);
            schemaBuilder.defineObjectClass(userSchemaInfo);

            ObjectClassInfo roleSchemaInfo = Auth0RoleHandler.getSchema(configuration);
            schemaBuilder.defineObjectClass(roleSchemaInfo);

            ObjectClassInfo organizationSchemaInfo = Auth0OrganizationHandler.getSchema(configuration);
            schemaBuilder.defineObjectClass(organizationSchemaInfo);

            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class);

            userSchemaMap = new HashMap<>();
            userSchemaInfo.getAttributeInfo().stream()
                    .forEach(a -> userSchemaMap.put(a.getName(), a));
            userSchemaMap = Collections.unmodifiableMap(userSchemaMap);

            roleSchemaMap = new HashMap<>();
            roleSchemaInfo.getAttributeInfo().stream()
                    .forEach(a -> roleSchemaMap.put(a.getName(), a));
            roleSchemaMap = Collections.unmodifiableMap(roleSchemaMap);

            organizationSchemaMap = new HashMap<>();
            organizationSchemaInfo.getAttributeInfo().stream()
                    .forEach(a -> organizationSchemaMap.put(a.getName(), a));
            organizationSchemaMap = Collections.unmodifiableMap(organizationSchemaMap);

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

    private Map<String, AttributeInfo> getRoleSchemaMap() {
        // Load schema map if it's not loaded yet
        if (roleSchemaMap == null) {
            schema();
        }
        return roleSchemaMap;
    }

    private Map<String, AttributeInfo> getOrganizationSchemaMap() {
        // Load schema map if it's not loaded yet
        if (organizationSchemaMap == null) {
            schema();
        }
        return organizationSchemaMap;
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass value not provided");
        }
        LOG.info("CREATE METHOD OBJECTCLASS VALUE: {0}", objectClass);

        if (createAttributes == null || createAttributes.isEmpty()) {
            throw new InvalidAttributeValueException("attributes not provided or empty");
        }

        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler userHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                return userHandler.createUser(createAttributes);

            } else if (objectClass.equals(ROLE_OBJECT_CLASS)) {
                Auth0RoleHandler roleHandler = new Auth0RoleHandler(configuration, client, getRoleSchemaMap());
                return roleHandler.createRole(createAttributes);

            } else if (objectClass.equals(ORGANIZATION_OBJECT_CLASS)) {
                Auth0OrganizationHandler organizationHandler = new Auth0OrganizationHandler(configuration, client, getOrganizationSchemaMap());
                return organizationHandler.create(createAttributes);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler userHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                return userHandler.updateDelta(uid, modifications, options);

            } else if (objectClass.equals(ROLE_OBJECT_CLASS)) {
                Auth0RoleHandler roleHandler = new Auth0RoleHandler(configuration, client, getRoleSchemaMap());
                return roleHandler.updateDelta(uid, modifications, options);

            } else if (objectClass.equals(ORGANIZATION_OBJECT_CLASS)) {
                Auth0OrganizationHandler organizationHandler = new Auth0OrganizationHandler(configuration, client, getOrganizationSchemaMap());
                return organizationHandler.updateDelta(uid, modifications, options);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }

        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler userHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                userHandler.deleteUser(uid, options);

            } else if (objectClass.equals(ROLE_OBJECT_CLASS)) {
                Auth0RoleHandler roleHandler = new Auth0RoleHandler(configuration, client, getRoleSchemaMap());
                roleHandler.deleteRole(uid, options);

            } else if (objectClass.equals(ORGANIZATION_OBJECT_CLASS)) {
                Auth0OrganizationHandler organizationHandler = new Auth0OrganizationHandler(configuration, client, getOrganizationSchemaMap());
                organizationHandler.delete(uid, options);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public FilterTranslator<Auth0Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new Auth0FilterTranslator(objectClass, options);
    }

    @Override
    public void executeQuery(ObjectClass objectClass, Auth0Filter filter, ResultsHandler resultsHandler, OperationOptions options) {
        try {
            if (objectClass.equals(USER_OBJECT_CLASS)) {
                Auth0UserHandler userHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                userHandler.getUsers(filter, resultsHandler, options);

            } else if (objectClass.equals(ROLE_OBJECT_CLASS)) {
                Auth0RoleHandler roleHandler = new Auth0RoleHandler(configuration, client, getRoleSchemaMap());
                roleHandler.getRoles(filter, resultsHandler, options);

            } else if (objectClass.equals(ORGANIZATION_OBJECT_CLASS)) {
                Auth0OrganizationHandler organizationHandler = new Auth0OrganizationHandler(configuration, client, getOrganizationSchemaMap());
                organizationHandler.query(filter, resultsHandler, options);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public void test() {
        try {
            dispose();
            initClient();
        } catch (Exception e) {
            throw processException(e);
        }
    }

    @Override
    public void dispose() {
        this.client = null;
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

    protected ConnectorException processException(Auth0Exception e) {
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
