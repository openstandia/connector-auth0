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

import jp.openstandia.connector.auth0.Auth0Configuration;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.BeforeEach;

import java.lang.reflect.Field;

public abstract class AbstractTest {

    protected ConnectorFacade connector;
    protected MockClient mockClient;

    protected Auth0Configuration newConfiguration() {
        Auth0Configuration conf = new Auth0Configuration();
        conf.setDomain("example.com");
        return conf;
    }

    protected ConnectorFacade newFacade() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(LocalAuth0Connector.class, newConfiguration());
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
}
