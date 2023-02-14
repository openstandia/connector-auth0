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
package jp.openstandia.connector.auth0.testutil;

import com.auth0.json.mgmt.users.Identity;
import com.auth0.json.mgmt.users.User;
import jp.openstandia.connector.auth0.Auth0Configuration;
import jp.openstandia.connector.auth0.Auth0UserHandler;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.BeforeEach;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractTest {

    protected ConnectorFacade connector;
    protected MockClient mockClient;

    protected static final String DEFAULT_CONNECTION = "Username-Password-Authentication";
    protected static final String SMS_CONNECTION = "sms";
    protected static final ObjectClass DEFAULT_USER_OBJECT_CLASS = new ObjectClass(Auth0UserHandler.USER_OBJECT_CLASS_PREFIX + DEFAULT_CONNECTION);
    protected static final ObjectClass SMS_USER_OBJECT_CLASS = new ObjectClass(Auth0UserHandler.USER_OBJECT_CLASS_PREFIX + SMS_CONNECTION);

    protected Auth0Configuration newConfiguration() {
        Auth0Configuration conf = new Auth0Configuration();
        conf.setDomain("example.com");
        return conf;
    }

    protected ConnectorFacade newFacade() {
        return newFacade(newConfiguration());
    }

    protected ConnectorFacade newFacade(Auth0Configuration conf) {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(LocalAuth0Connector.class, conf);
        impl.getResultsHandlerConfiguration().setEnableAttributesToGetSearchResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableNormalizingResultsHandler(false);
        impl.getResultsHandlerConfiguration().setEnableFilteredResultsHandler(false);
        return factory.newInstance(impl);
    }

    @BeforeEach
    void before() {
        connector = newFacade();
        mockClient = MockClient.instance();
        mockClient.init();
    }

    public static String getString(Object o, String fieldName) {
        try {
            Field f = o.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            return (String) f.get(o);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setObject(Object o, String fieldName, Object value) {
        try {
            Field f = o.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(o, value);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    public static User newResponseUser(String userId, String connection) {
        Identity identity = new Identity();
        setObject(identity, "connection", connection);
        List<Identity> identities = new ArrayList<>();
        identities.add(identity);

        User user = new User();
        user.setId(userId);
        setObject(user, "identities", identities);

        return user;
    }
}
