using System.Collections.ObjectModel;

namespace MultiFactor.Radius.Adapter.Services.Ldap
{
    public interface ILdapAttributes
    {     
        /// <summary>
        /// Returns all existed attributes names.
        /// </summary>
        ReadOnlyCollection<string> Keys { get; }

        /// <summary>
        /// Returns TRUE if the specified attribute exists in collection.
        /// </summary>
        /// <param name="attribute">Atribute name.</param>
        /// <returns>True or False</returns>
        bool Has(string attribute);

        /// <summary>
        /// Returns the first value of the specified attribute.
        /// </summary>
        /// <param name="attribute">Attribute name.</param>
        /// <returns>String representation of attribute value.</returns>
        string GetValue(string attribute);

        /// <summary>
        /// Returns all presented value of the specified attribute.
        /// </summary>
        /// <param name="attribute">Attribute name.</param>
        /// <returns>Collection of the String representation of attribute value.</returns>
        ReadOnlyCollection<string> GetValues(string attribute);
    }
}