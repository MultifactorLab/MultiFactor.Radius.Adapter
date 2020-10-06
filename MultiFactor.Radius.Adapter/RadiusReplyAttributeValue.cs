using MultiFactor.Radius.Adapter.Server;
using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter
{
    /// <summary>
    /// Radius Access-Accept message extra element
    /// </summary>
    public class RadiusReplyAttributeValue
    {
        public RadiusReplyAttributeValue(object value, string conditionClause)
        {
            Value = value;
            if (!string.IsNullOrEmpty(conditionClause))
            {
                ParseConditionClause(conditionClause);
            }
        }

        /// <summary>
        /// Attribute Value
        /// </summary>
        public object Value { get; }


        /// <summary>
        /// Return condition
        /// </summary>
        public string UserGroupCondition { get; set; }

        /// <summary>
        /// Is match condition
        /// </summary>
        public bool IsMatch(PendingRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (string.IsNullOrEmpty(UserGroupCondition))
            {
                return true; //always on
            }

            var isInGroup = request
                .UserGroups
                .Any(g => string.Compare(g, UserGroupCondition, StringComparison.InvariantCultureIgnoreCase) == 0);
            
            return isInGroup;
        }

        private void ParseConditionClause(string clause)
        {
            var parts = clause.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries);

            switch (parts[0])
            {
                case "UserGroup":
                    UserGroupCondition = parts[1];
                    break;
                default:
                    throw new Exception($"Unknown condition '{clause}'");
            }
        }
    }
}
