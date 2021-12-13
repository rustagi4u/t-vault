import api from '../../../services';
// get calls
const getAppRole = () => api.get('/ss/approle');
const fetchAppRole = (appRole) => api.get(`/ss/approle/role/${appRole}`);
const fetchAppRoleDetails = (appRole) => api.get(`/ss/approle/${appRole}`);
const getAccessors = (appRole) => api.get(`/ss/approle/${appRole}/accessors`);
const getRoleId = (appRole) => api.get(`/ss/approle/${appRole}/role_id`);
const getAppRoleOwner = (appRole) => api.get(`/ss/approle/${appRole}/owner`);
const getUserName = (user) => api.get(`/ldap/ntusers?displayName=${user}`);
const getTmoUsers = (user) => api.get(`/tmo/users?UserPrincipalName=${user}`);
const getEntitiesAssociatedWithAppRole = (appRole) => api.get(`/ss/approle/list/associations/${appRole}`);

// put calls
const updateAppRole = (payload) => api.put('/ss/approle', payload);

// post calls
const createAppRole = (payload) => api.post('/ss/auth/approle/role', payload);
const createSecretId = (appRole) => api.get(`/ss/approle/${appRole}/secret_id`);

// delete calls
const deleteAppRole = (appRole) =>
  api.delete(`/ss/auth/approle/role/${appRole}`);
const deleteSecretIds = (payload) =>
  api.delete(`/ss/approle/${payload.role_name}/secret_id`, payload);

export default {
  getAppRole,
  fetchAppRole,
  fetchAppRoleDetails,
  updateAppRole,
  createAppRole,
  createSecretId,
  getAccessors,
  deleteSecretIds,
  getRoleId,
  deleteAppRole,
  getAppRoleOwner,
  getUserName,
  getTmoUsers,
  getEntitiesAssociatedWithAppRole,
};
