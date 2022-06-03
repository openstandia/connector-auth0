package jp.openstandia.connector.auth0;

import com.auth0.client.mgmt.filter.PageFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.Page;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class Auth0ClientTest {

    @Test
    void zeroWithFullPage() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 50;

        // When
        int i = client.withAuthPaging(filter, 0, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(limit, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            Page<User> response = new UsersPage(0, users.size(), users.size(), limit, null, users);
            return response;
        });

        // Then
        assertEquals(0, i);
    }

    @Test
    void oneWithFullPage() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 50;

        // When
        int i = client.withAuthPaging(filter, 0, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(limit, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            users.add(newUser("1"));
            Page<User> response = new UsersPage(0, users.size(), users.size(), limit, null, users);
            return response;
        });

        // Then
        assertEquals(1, i);
    }

    @Test
    void twoWithFullPage() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 50;

        // When
        int i = client.withAuthPaging(filter, 0, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(limit, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            users.add(newUser("1"));
            users.add(newUser("2"));
            Page<User> response = new UsersPage(0, users.size(), users.size(), limit, null, users);
            return response;
        });

        // Then
        assertEquals(2, i);
    }

    @Test
    void nextPageWithFullPage() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        AtomicInteger count = new AtomicInteger(0);
        int i = client.withAuthPaging(filter, 0, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);

            switch (count.incrementAndGet()) {
                case 1: {
                    assertEquals(0, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    users.add(newUser("1"));
                    users.add(newUser("2"));
                    Page<User> response = new UsersPage(0, users.size(), 3, limit, null, users);
                    return response;
                }
                case 2: {
                    assertEquals(1, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    users.add(newUser("3"));
                    Page<User> response = new UsersPage(2, users.size(), 3, limit, null, users);
                    return response;
                }
            }
            fail("Unexpected called");
            return null;
        });

        // Then
        assertEquals(3, i);
        assertEquals(2, count.get());
    }

    @Test
    void countZero() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();

        // When
        // For count requested, pageOffset and pageSize are 1
        int i = client.withAuthPaging(filter, 1, 1, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(1, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            Page<User> response = new UsersPage(0, users.size(), users.size(), 1, null, users);
            return response;
        });

        // Then
        assertEquals(0, i);
    }

    @Test
    void countOne() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();

        // When
        // For count requested, pageOffset and pageSize are 1
        int i = client.withAuthPaging(filter, 1, 1, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(1, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            users.add(newUser("1"));
            Page<User> response = new UsersPage(0, users.size(), users.size(), 1, null, users);
            return response;
        });

        // Then
        assertEquals(1, i);
    }

    @Test
    void zeroWithOffset() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        int i = client.withAuthPaging(filter, 1, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(limit, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            Page<User> response = new UsersPage(0, users.size(), 0, limit, null, users);
            return response;
        });

        // Then
        assertEquals(0, i);
    }

    @Test
    void oneWithOffset() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        int i = client.withAuthPaging(filter, 1, limit, (f, skipCount) -> {
            assertEquals(0, skipCount);
            assertEquals(0, filter.getAsMap().get("page"));
            assertEquals(limit, filter.getAsMap().get("per_page"));

            List<User> users = new ArrayList<>();
            users.add(newUser("1"));
            Page<User> response = new UsersPage(0, users.size(), 1, limit, null, users);
            return response;
        });

        // Then
        assertEquals(1, i);
    }

    @Test
    void oneWithOffset2() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        AtomicInteger count = new AtomicInteger(0);
        int i = client.withAuthPaging(filter, 2, limit, (f, skipCount) -> {
            switch (count.incrementAndGet()) {
                case 1: {
                    assertEquals(1, skipCount);
                    assertEquals(0, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    // skipped by skipCount
                    // users.add(newUser("1"));
                    Page<User> response = new UsersPage(1, users.size(), 1, limit, null, users);
                    return response;
                }
            }
            fail("Unexpected called");
            return null;
        });

        // Then
        assertEquals(1, i);
        assertEquals(1, count.get());
    }

    @Test
    void threeWithOffset2() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        AtomicInteger count = new AtomicInteger(0);
        int i = client.withAuthPaging(filter, 2, limit, (f, skipCount) -> {
            switch (count.incrementAndGet()) {
                case 1: {
                    assertEquals(1, skipCount);
                    assertEquals(0, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    // skipped by skipCount
                    // users.add(newUser("1"));
                    users.add(newUser("2"));
                    Page<User> response = new UsersPage(1, users.size(), 3, limit, null, users);
                    return response;
                }
                case 2: {
                    assertEquals(0, skipCount);
                    assertEquals(1, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    users.add(newUser("3"));
                    Page<User> response = new UsersPage(1, users.size(), 3, limit, null, users);
                    return response;
                }
            }
            fail("Unexpected called");
            return null;
        });

        // Then
        assertEquals(3, i);
        assertEquals(2, count.get());
    }

    @Test
    void threeWithOffset3() throws Auth0Exception {
        Auth0Client client = new Auth0Client() {
            @Override
            protected <T> T withAuth(APIFunction<T> callback) throws Auth0Exception {
                return callback.apply();
            }
        };

        // Given
        PageFilter filter = new PageFilter();
        int limit = 2;

        // When
        AtomicInteger count = new AtomicInteger(0);
        int i = client.withAuthPaging(filter, 3, limit, (f, skipCount) -> {
            switch (count.incrementAndGet()) {
                case 1: {
                    assertEquals(0, skipCount);
                    assertEquals(1, filter.getAsMap().get("page"));
                    assertEquals(limit, filter.getAsMap().get("per_page"));

                    List<User> users = new ArrayList<>();
                    users.add(newUser("3"));
                    Page<User> response = new UsersPage(2, users.size(), 3, limit, null, users);
                    return response;
                }
            }
            fail("Unexpected called");
            return null;
        });

        // Then
        assertEquals(3, i);
        assertEquals(1, count.get());
    }

    private User newUser(String id) {
        User user = new User("test");
        user.setId(id);
        return user;
    }
}