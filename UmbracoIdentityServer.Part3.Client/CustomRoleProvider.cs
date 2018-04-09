using IdentityModel;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using Umbraco.Web.Security.Providers;

namespace UmbracoIdentityServer.Part3.Client
{
    public class CustomRoleProvider : MembersRoleProvider
    {
        #region Read Only Functions  
        /// <summary>
        /// read only in this provider
        /// <see cref="RoleProvider.AddUsersToRoles"/>
        /// </summary>
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            throw new AccessViolationException("This Provider is Read-Only");
        }

        /// <summary>
        /// read only in this provider
        /// <see cref="RoleProvider.CreateRole"/>
        /// </summary>
        public override void CreateRole(string roleName)
        {
            throw new AccessViolationException("This Provider is Read-Only");
        }

        /// <summary>
        /// read only in this provider
        /// <see cref="RoleProvider.DeleteRole"/>
        /// </summary>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            throw new AccessViolationException("This Provider is Read-Only");
        }

        /// <summary>
        /// read only in this provider
        /// <see cref="RoleProvider.RemoveUsersFromRoles"/>
        /// </summary>
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            throw new AccessViolationException("This Provider is Read-Only");
        }
        #endregion 

        /// <summary>
        /// return all the roles
        /// </summary>
        /// <returns>string array of portal security roles</returns>
        public override string[] GetAllRoles()
        {
            return new[] { "Standard User" };
        }

        /// <summary>
        /// returns the roles for a user
        /// </summary>
        /// <param name="username"></param>
        /// <returns>string array of portal security roles</returns>
        public override string[] GetRolesForUser(string username)
        {
            var userIdentity = (ClaimsIdentity)Thread.CurrentPrincipal.Identity;

            var roles = userIdentity.Claims.Where(c => c.Type.Equals(JwtClaimTypes.Role)).Select(c => c.Value).ToArray();

            return roles;
        }

        /// <summary>
        /// checks user to see if they are in a role
        /// 
        /// returns true if the user is in the role listed
        /// 
        /// </summary>
        /// <param name="username">name of user </param>
        /// <param name="roleName">role name to search for</param>
        /// <returns>true if they have the portal security role</returns>
        public override bool IsUserInRole(string username, string roleName)
        {
            string[] userRoles = GetRolesForUser(username);
            return userRoles.Contains(roleName);
        }

        /// <summary>
        /// checks if a role exsits
        /// </summary>
        /// <param name="roleName">name of role</param>
        /// <returns>true if role is in the list</returns>
        public override bool RoleExists(string roleName)
        {
            return GetAllRoles().Contains(roleName);
        }

        #region Not Implimented Functions
        /// <summary>
        /// Not Implimented in provider
        /// <see cref="RoleProvider.GetUsersInRole"/>
        /// </summary>
        /// <param name="roleName">Name of Role</param>
        /// <returns>List of Users in role</returns>
        public override string[] GetUsersInRole(string roleName)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Not Implimented in provider
        /// <see cref="RoleProvider.FindUsersInRole"/>
        /// </summary>
        /// <param name="roleName">Name of Role</param>
        /// <param name="usernameToMatch">UserName string to match</param>
        /// <returns></returns>
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            throw new NotImplementedException();
        }
        #endregion 

    }
}