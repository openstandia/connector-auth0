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

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkResponse;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListGroupsIterable;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersInGroupIterable;
import software.amazon.awssdk.services.cognitoidentityprovider.paginators.ListUsersIterable;

import java.util.function.Function;

public class MockClient implements CognitoIdentityProviderClient {

    private static final MockClient INSTANCE = new MockClient();

    public boolean closed = false;

    // User
    private Function<AdminCreateUserRequest, AdminCreateUserResponse> adminCreateUser;
    private Function<AdminEnableUserRequest, AdminEnableUserResponse> adminEnableUser;
    private Function<AdminDisableUserRequest, AdminDisableUserResponse> adminDisableUser;
    private Function<AdminSetUserPasswordRequest, AdminSetUserPasswordResponse> adminSetUserPassword;
    private Function<AdminUpdateUserAttributesRequest, AdminUpdateUserAttributesResponse> adminUpdateUserAttributes;
    private Function<AdminDeleteUserRequest, AdminDeleteUserResponse> adminDeleteUser;
    private Function<AdminAddUserToGroupRequest, AdminAddUserToGroupResponse> adminAddUserToGroup;
    private Function<AdminRemoveUserFromGroupRequest, AdminRemoveUserFromGroupResponse> adminRemoveUserFromGroup;

    // Group
    private Function<CreateGroupRequest, CreateGroupResponse> createGroup;
    private Function<UpdateGroupRequest, UpdateGroupResponse> updateGroup;
    private Function<DeleteGroupRequest, DeleteGroupResponse> deleteGroup;
    private Function<ListUsersInGroupRequest, ListUsersInGroupResponse> listUsersInGroup;
    private Function<ListUsersInGroupRequest, ListUsersInGroupIterable> listUsersInGroupPaginator;

    // executeQuery
    // User
    private Function<AdminGetUserRequest, AdminGetUserResponse> adminGetUser;
    private Function<ListUsersRequest, ListUsersResponse> listUsers;
    private Function<ListUsersRequest, ListUsersIterable> listUsersPaginator;
    // Group
    private Function<GetGroupRequest, GetGroupResponse> getGroup;
    private Function<ListGroupsRequest, ListGroupsResponse> listGroups;
    private Function<ListGroupsRequest, ListGroupsIterable> listGroupsPaginator;

    public void init() {
        closed = false;
        adminCreateUser = null;
        adminEnableUser = null;
        adminDisableUser = null;
        adminSetUserPassword = null;
        adminUpdateUserAttributes = null;
        adminDeleteUser = null;
        adminAddUserToGroup = null;
        adminRemoveUserFromGroup = null;

        createGroup = null;
        updateGroup = null;
        deleteGroup = null;
        listUsersInGroup = null;
        listUsersInGroupPaginator = null;

        adminGetUser = null;
        listUsers = null;
        listUsersPaginator = null;

        getGroup = null;
        listGroups = null;
        listGroupsPaginator = null;
    }

    private MockClient() {
    }

    public static MockClient instance() {
        return INSTANCE;
    }

    public static <T> T buildSuccess(CognitoIdentityProviderResponse.Builder builder, Class<T> clazz) {
        SdkResponse response = builder.sdkHttpResponse(SdkHttpResponse.builder().statusCode(200).build()).build();
        return (T) response;
    }

    public static UsernameExistsException userExistsError() {
        return UsernameExistsException.builder().statusCode(400).build();
    }

    public static UserNotFoundException userNotFoundError() {
        return UserNotFoundException.builder().statusCode(400).build();
    }

    public static GroupExistsException groupExistsError() {
        return GroupExistsException.builder().statusCode(400).build();
    }

    public static ResourceNotFoundException groupNotFoundError() {
        return ResourceNotFoundException.builder().statusCode(400).build();
    }

    @Override
    public String serviceName() {
        return "mock";
    }

    @Override
    public void close() {
        closed = true;
    }

    @Override
    public DescribeUserPoolResponse describeUserPool(DescribeUserPoolRequest request) throws AwsServiceException, SdkClientException {
        DescribeUserPoolResponse.Builder builder = DescribeUserPoolResponse.builder()
                .userPool(UserPoolType.builder()
                        .schemaAttributes(
                                SchemaAttributeType.builder()
                                        .name("sub")
                                        .attributeDataType(AttributeDataType.STRING)
                                        .mutable(false)
                                        .required(false)
                                        .build(),
                                SchemaAttributeType.builder()
                                        .name("email")
                                        .attributeDataType(AttributeDataType.STRING)
                                        .mutable(true)
                                        .required(false)
                                        .build(),
                                SchemaAttributeType.builder()
                                        .name("custom:string")
                                        .attributeDataType(AttributeDataType.STRING)
                                        .mutable(true)
                                        .required(false)
                                        .build(),
                                SchemaAttributeType.builder()
                                        .name("custom:integer")
                                        .attributeDataType(AttributeDataType.NUMBER)
                                        .mutable(true)
                                        .required(false)
                                        .build(),
                                SchemaAttributeType.builder()
                                        .name("custom:datetime")
                                        .attributeDataType(AttributeDataType.DATE_TIME)
                                        .mutable(true)
                                        .required(false)
                                        .build(),
                                SchemaAttributeType.builder()
                                        .name("custom:boolean")
                                        .attributeDataType(AttributeDataType.BOOLEAN)
                                        .mutable(true)
                                        .required(false)
                                        .build()
                        )
                        .usernameConfiguration(UsernameConfigurationType.builder().caseSensitive(true).build())
                        .build());

        return buildSuccess(builder, DescribeUserPoolResponse.class);
    }

    public void adminCreateUser(Function<AdminCreateUserRequest, AdminCreateUserResponse> mock) {
        this.adminCreateUser = mock;
    }

    @Override
    public AdminCreateUserResponse adminCreateUser(AdminCreateUserRequest request) throws AwsServiceException, SdkClientException {
        return adminCreateUser.apply(request);
    }

    public void adminEnableUser(Function<AdminEnableUserRequest, AdminEnableUserResponse> mock) {
        this.adminEnableUser = mock;
    }

    @Override
    public AdminEnableUserResponse adminEnableUser(AdminEnableUserRequest request) throws AwsServiceException, SdkClientException {
        return adminEnableUser.apply(request);
    }

    public void adminDisableUser(Function<AdminDisableUserRequest, AdminDisableUserResponse> mock) {
        this.adminDisableUser = mock;
    }

    @Override
    public AdminDisableUserResponse adminDisableUser(AdminDisableUserRequest request) throws AwsServiceException, SdkClientException {
        return adminDisableUser.apply(request);
    }

    public void adminSetUserPassword(Function<AdminSetUserPasswordRequest, AdminSetUserPasswordResponse> mock) {
        this.adminSetUserPassword = mock;
    }

    @Override
    public AdminSetUserPasswordResponse adminSetUserPassword(AdminSetUserPasswordRequest request) throws AwsServiceException, SdkClientException {
        return adminSetUserPassword.apply(request);
    }

    public void adminUpdateUserAttributes(Function<AdminUpdateUserAttributesRequest, AdminUpdateUserAttributesResponse> mock) {
        this.adminUpdateUserAttributes = mock;
    }

    @Override
    public AdminDeleteUserResponse adminDeleteUser(AdminDeleteUserRequest request) throws AwsServiceException, SdkClientException {
        return adminDeleteUser.apply(request);
    }

    public void adminDeleteUser(Function<AdminDeleteUserRequest, AdminDeleteUserResponse> mock) {
        this.adminDeleteUser = mock;
    }

    @Override
    public AdminAddUserToGroupResponse adminAddUserToGroup(AdminAddUserToGroupRequest request) throws AwsServiceException, SdkClientException {
        return adminAddUserToGroup.apply(request);
    }

    public void adminAddUserToGroup(Function<AdminAddUserToGroupRequest, AdminAddUserToGroupResponse> mock) {
        this.adminAddUserToGroup = mock;
    }

    @Override
    public AdminRemoveUserFromGroupResponse adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest request) throws AwsServiceException, SdkClientException {
        return adminRemoveUserFromGroup.apply(request);
    }

    public void adminRemoveUserFromGroup(Function<AdminRemoveUserFromGroupRequest, AdminRemoveUserFromGroupResponse> mock) {
        this.adminRemoveUserFromGroup = mock;
    }

    @Override
    public AdminUpdateUserAttributesResponse adminUpdateUserAttributes(AdminUpdateUserAttributesRequest request) throws AwsServiceException, SdkClientException {
        return adminUpdateUserAttributes.apply(request);
    }

    @Override
    public CreateGroupResponse createGroup(CreateGroupRequest request) throws AwsServiceException, SdkClientException {
        return createGroup.apply(request);
    }

    public void createGroup(Function<CreateGroupRequest, CreateGroupResponse> mock) {
        this.createGroup = mock;
    }

    @Override
    public UpdateGroupResponse updateGroup(UpdateGroupRequest request) throws AwsServiceException, SdkClientException {
        return updateGroup.apply(request);
    }

    public void updateGroup(Function<UpdateGroupRequest, UpdateGroupResponse> mock) {
        this.updateGroup = mock;
    }

    @Override
    public DeleteGroupResponse deleteGroup(DeleteGroupRequest request) throws AwsServiceException, SdkClientException {
        return deleteGroup.apply(request);
    }

    public void deleteGroup(Function<DeleteGroupRequest, DeleteGroupResponse> mock) {
        this.deleteGroup = mock;
    }

    @Override
    public ListUsersInGroupResponse listUsersInGroup(ListUsersInGroupRequest request) throws AwsServiceException, SdkClientException {
        return listUsersInGroup.apply(request);
    }

    public void listUsersInGroup(Function<ListUsersInGroupRequest, ListUsersInGroupResponse> mock) {
        this.listUsersInGroup = mock;
    }

    @Override
    public ListUsersInGroupIterable listUsersInGroupPaginator(ListUsersInGroupRequest request) throws AwsServiceException, SdkClientException {
        return listUsersInGroupPaginator.apply(request);
    }

    public void listUsersInGroupPaginator(Function<ListUsersInGroupRequest, ListUsersInGroupIterable> mock) {
        this.listUsersInGroupPaginator = mock;
    }

    @Override
    public AdminGetUserResponse adminGetUser(AdminGetUserRequest request) throws AwsServiceException, SdkClientException {
        return adminGetUser.apply(request);
    }

    public void adminGetUser(Function<AdminGetUserRequest, AdminGetUserResponse> mock) {
        this.adminGetUser = mock;
    }

    @Override
    public ListUsersResponse listUsers(ListUsersRequest request) throws AwsServiceException, SdkClientException {
        return listUsers.apply(request);
    }

    public void listUsers(Function<ListUsersRequest, ListUsersResponse> mock) {
        this.listUsers = mock;
    }

    @Override
    public ListUsersIterable listUsersPaginator(ListUsersRequest request) throws AwsServiceException, SdkClientException {
        return listUsersPaginator.apply(request);
    }

    public void listUsersPaginator(Function<ListUsersRequest, ListUsersIterable> mock) {
        this.listUsersPaginator = mock;
    }

    @Override
    public GetGroupResponse getGroup(GetGroupRequest request) throws AwsServiceException, SdkClientException {
        return getGroup.apply(request);
    }

    public void getGroup(Function<GetGroupRequest, GetGroupResponse> mock) {
        this.getGroup = mock;
    }

    @Override
    public ListGroupsResponse listGroups(ListGroupsRequest request) throws AwsServiceException, SdkClientException {
        return listGroups.apply(request);
    }

    public void listGroups(Function<ListGroupsRequest, ListGroupsResponse> mock) {
        this.listGroups = mock;
    }

    @Override
    public ListGroupsIterable listGroupsPaginator(ListGroupsRequest request) throws AwsServiceException, SdkClientException {
        return listGroupsPaginator.apply(request);
    }

    public void listGroupsPaginator(Function<ListGroupsRequest, ListGroupsIterable> mock) {
        this.listGroupsPaginator = mock;
    }
}
