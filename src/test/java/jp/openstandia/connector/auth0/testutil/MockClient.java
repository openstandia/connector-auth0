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

import com.auth0.client.mgmt.filter.ConnectionFilter;
import com.auth0.client.mgmt.filter.FieldsFilter;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.APIException;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Connection;
import com.auth0.json.mgmt.users.User;
import jp.openstandia.connector.auth0.Auth0Client;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MockClient extends Auth0Client {

    private static final MockClient INSTANCE = new MockClient();

    // User
    public MockFunction<User, User> createUser;
    public MockBiConsumer<Uid, User> updateUser;
    public MockBiFunction<String, FieldsFilter, User> getUserByUid;
    public MockBiFunction<String, FieldsFilter, List<User>> getUserByEmail;
    public MockFunction<UserFilter, List<User>> getUsersByFilter;
    public MockThreeConsumer<UserFilter, OperationOptions, Auth0Client.ResultHandlerFunction<User, Boolean>> getUsers;
    public MockConsumer<Uid> deleteUser;

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
    public List<Connection> getConnection(ConnectionFilter connectionFilter) throws Auth0Exception {
        List<Connection> connections = new ArrayList<>();
        connections.add(new Connection("Username-Password-Authentication", "auth0"));
        connections.add(new Connection("sms", "sms"));
        return connections;
    }

    @Override
    public User createUser(User newUser) throws Auth0Exception {
        return createUser.apply(newUser);
    }

    @Override
    public void updateUser(Uid uid, User patchUser) throws Auth0Exception {
        updateUser.accept(uid, patchUser);
    }

    @Override
    public User getUserByUid(String userId, UserFilter filter) throws Auth0Exception {
        return getUserByUid.apply(userId, filter);
    }

    @Override
    public List<User> getUserByEmail(String email, FieldsFilter filter) throws Auth0Exception {
        return getUserByEmail.apply(email, filter);
    }

    @Override
    public List<User> getUsersByFilter(UserFilter filter) throws Auth0Exception {
        return getUsersByFilter.apply(filter);
    }

    @Override
    public void getUsers(UserFilter userFilter, OperationOptions options, Auth0Client.ResultHandlerFunction<User, Boolean> resultsHandler) throws Auth0Exception {
        getUsers.accept(userFilter, options, resultsHandler);
    }

    @Override
    public void deleteUser(Uid uid) throws Auth0Exception {
        deleteUser.accept(uid);
    }

    @FunctionalInterface
    public interface MockFunction<T, R> {
        R apply(T t) throws Auth0Exception;
    }

    @FunctionalInterface
    public interface MockBiFunction<T, U, R> {
        R apply(T t, U u) throws Auth0Exception;
    }

    @FunctionalInterface
    public interface MockConsumer<T> {
        void accept(T t) throws Auth0Exception;
    }

    @FunctionalInterface
    public interface MockBiConsumer<T, U> {
        void accept(T t, U u) throws Auth0Exception;
    }

    @FunctionalInterface
    public interface MockThreeConsumer<T, U, V> {
        void accept(T t, U u, V v) throws Auth0Exception;
    }
}
