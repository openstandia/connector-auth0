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
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.apache.ProxyConfiguration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClientBuilder;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.net.URI;
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
            throw processRuntimeException(e);
        }

        LOG.ok("Connector {0} successfully initialized", getClass().getName());
    }

    protected void authenticateResource() {
        // Setup http proxy aware httpClient
        ApacheHttpClient.Builder httpClientBuilder = ApacheHttpClient.builder();

        if (StringUtil.isNotEmpty(configuration.getHttpProxyHost())) {
            ProxyConfiguration.Builder proxyBuilder = ProxyConfiguration.builder()
                    .endpoint(URI.create(String.format("http://%s:%d",
                            configuration.getHttpProxyHost(), configuration.getHttpProxyPort())));
            if (StringUtil.isNotEmpty(configuration.getHttpProxyUser()) && configuration.getHttpProxyPassword() != null) {
                configuration.getHttpProxyPassword().access(c -> {
                    proxyBuilder.username(configuration.getHttpProxyUser())
                            .password(String.valueOf(c));
                });
            }
            httpClientBuilder.proxyConfiguration(proxyBuilder.build());
        }

        // Setup AWS credential using IAM Role or specified access key
        final AwsCredentialsProvider[] cp = {DefaultCredentialsProvider.create()};
        if (configuration.getAWSAccessKeyID() != null && configuration.getAWSSecretAccessKey() != null) {
            configuration.getAWSAccessKeyID().access(c -> {
                configuration.getAWSSecretAccessKey().access(s -> {
                    AwsCredentials cred = AwsBasicCredentials.create(String.valueOf(c), String.valueOf(s));
                    cp[0] = StaticCredentialsProvider.create(cred);
                });
            });
        }

        // If assumeRoleArn is configured, override AWS credential by getting temporary credential.
        if (StringUtil.isNotEmpty(configuration.getAssumeRoleArn())) {
            StsClient stsClient = StsClient.builder()
                    .credentialsProvider(cp[0])
                    .httpClientBuilder(httpClientBuilder).build();

            AssumeRoleRequest.Builder builder = AssumeRoleRequest.builder()
                    .roleArn(configuration.getAssumeRoleArn());
            if (StringUtil.isNotEmpty(configuration.getAssumeRoleExternalId())) {
                builder.externalId(configuration.getAssumeRoleExternalId());
            }
            AssumeRoleRequest req = builder
                    .durationSeconds(configuration.getAssumeRoleDurationSeconds())
                    .roleSessionName("identity-connector")
                    .build();

            StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                    .stsClient(stsClient)
                    .refreshRequest(req)
                    .build();

            cp[0] = provider;
        }

        // Finally, setup cognito client using http client and AWS credential
        CognitoIdentityProviderClientBuilder builder = CognitoIdentityProviderClient.builder().credentialsProvider(cp[0]);

        String region = configuration.getRegion();
        if (StringUtil.isNotEmpty(region)) {
            try {
                Region r = Region.of(region);
                builder.region(r);
            } catch (IllegalArgumentException e) {
                LOG.error(e, "Invalid AWS region: {0}", region);
                throw new ConfigurationException("Invalid AWS region: " + region);
            }
        }

        client = builder.httpClientBuilder(httpClientBuilder).build();

        // Verify we can access the user pool
        describeUserPool();
    }

    private UserPoolType describeUserPool() {
        DescribeUserPoolResponse result = client.describeUserPool(DescribeUserPoolRequest.builder()
                .userPoolId(configuration.getUserPoolID()).build());
        int status = result.sdkHttpResponse().statusCode();
        if (status != 200) {
            throw new ConnectorIOException("Failed to describe user pool: " + configuration.getUserPoolID());
        }
        return result.userPool();
    }

    @Override
    public Schema schema() {
        try {
            UserPoolType userPoolType = describeUserPool();

            SchemaBuilder schemaBuilder = new SchemaBuilder(Auth0Connector.class);

            ObjectClassInfo userSchemaInfo = Auth0UserHandler.getUserSchema(userPoolType);
            schemaBuilder.defineObjectClass(userSchemaInfo);

            ObjectClassInfo groupSchemaInfo = Auth0RoleHandler.getGroupSchema(userPoolType);
            schemaBuilder.defineObjectClass(groupSchemaInfo);

            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
            schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class);

            userSchemaMap = new HashMap<>();
            userSchemaInfo.getAttributeInfo().stream()
                    .forEach(a -> userSchemaMap.put(a.getName(), a));
            userSchemaMap.put(Uid.NAME, AttributeInfoBuilder.define("username").build());
            userSchemaMap = Collections.unmodifiableMap(userSchemaMap);

            return schemaBuilder.build();

        } catch (RuntimeException e) {
            throw processRuntimeException(e);
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
                Auth0UserHandler usersHandler = new Auth0UserHandler(configuration, client, getUserSchemaMap());
                return usersHandler.createUser(createAttributes);

            } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                return groupsHandler.createGroup(createAttributes);

            } else {
                throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
            }
        } catch (RuntimeException e) {
            throw processRuntimeException(e);
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
            throw processRuntimeException(e);
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
            throw processRuntimeException(e);
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
                throw processRuntimeException(e);
            }

        } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
            try {
                Auth0RoleHandler groupsHandler = new Auth0RoleHandler(configuration, client);
                groupsHandler.getGroups(filter, resultsHandler, options);
            } catch (ResourceNotFoundException e) {
                // Don't throw UnknownUidException
                return;
            } catch (RuntimeException e) {
                throw processRuntimeException(e);
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
            throw processRuntimeException(e);
        }
    }

    @Override
    public void dispose() {
        client.close();
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

    protected ConnectorException processRuntimeException(RuntimeException e) {
        if (e instanceof ConnectorException) {
            return (ConnectorException) e;
        }
        if (e instanceof CognitoIdentityProviderException) {
            return processCognitoIdentityProviderException((CognitoIdentityProviderException) e);
        }
        return new ConnectorException(e);
    }

    private ConnectorException processCognitoIdentityProviderException(CognitoIdentityProviderException e) {
        if (e instanceof InvalidParameterException) {
            return new InvalidAttributeValueException(e);
        }
        if (e instanceof UserNotFoundException) {
            return new UnknownUidException(e);
        }
        if (e instanceof ResourceNotFoundException) {
            return new UnknownUidException(e);
        }
        if (e instanceof UsernameExistsException) {
            return new AlreadyExistsException(e);
        }
        if (e instanceof GroupExistsException) {
            return new AlreadyExistsException(e);
        }
        if (e instanceof LimitExceededException) {
            return RetryableException.wrap(e.getMessage(), e);
        }
        if (e instanceof TooManyRequestsException) {
            return RetryableException.wrap(e.getMessage(), e);
        }
        if (e instanceof InternalErrorException) {
            return RetryableException.wrap(e.getMessage(), e);
        }
        throw new ConnectorIOException(e);
    }
}
