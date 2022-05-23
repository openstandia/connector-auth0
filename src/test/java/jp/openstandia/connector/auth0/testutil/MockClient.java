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

import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.users.User;
import jp.openstandia.connector.auth0.Auth0Client;

import java.util.HashMap;
import java.util.Map;

public class MockClient extends Auth0Client {

    private static final MockClient INSTANCE = new MockClient();

    // User
    public MockFunction<User, User> createUser;

    private MockClient() {
    }

    public static MockClient instance() {
        return INSTANCE;
    }

    public void init() {
        this.createUser = null;
    }

    /**
     * {
     * "statusCode": 409,
     * "error": "Conflict",
     * "message": "The user already exists.",
     * "errorCode": "auth0_idp_error"
     * }
     *
     * @return
     */
    public static APIException userExistsError() {
        Map<String, Object> values = new HashMap<>();
        values.put("statusCode", 409);
        values.put("error", "Conflict");
        values.put("message", "The user already exists.");
        values.put("errorCode", "auth0_idp_error");
        return new APIException(values, 409);
    }

    @Override
    public User createUser(User newUser) throws Auth0Exception {
        return createUser.apply(newUser);
    }

    @FunctionalInterface
    public interface MockFunction<T, R> {
        R apply(T t) throws Auth0Exception;
    }
}