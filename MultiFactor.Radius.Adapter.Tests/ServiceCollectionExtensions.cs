using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;
using System.Linq;

namespace MultiFactor.Radius.Adapter.Tests
{
    internal static class ServiceCollectionExtensions
    {
        public static IServiceCollection RemoveService<TService>(this IServiceCollection services) where TService : class
        {
            services.RemoveAll<TService>();
            return services;
        }

        public static bool HasDescriptor<TService>(this IServiceCollection services) where TService : class
        {
            return services.FirstOrDefault(x => x.ServiceType == typeof(TService)) != null;
        }

        /// <summary>
        /// Replaces <typeparamref name="TService"/> implementation to <typeparamref name="TImplementation"/> if the service collection contains <typeparamref name="TService"/> descriptor.
        /// </summary>
        /// <typeparam name="TService">Abstraction type.</typeparam>
        /// <typeparam name="TImplementation">Implementation type.</typeparam>
        /// <param name="services">Service Collection</param>
        /// <returns><see cref="IServiceCollection"/> for chaining.</returns>
        public static IServiceCollection ReplaceService<TService, TImplementation>(this IServiceCollection services)
            where TService : class where TImplementation : class, TService
        {
            var descriptor = services.SingleOrDefault(x => x.ServiceType == typeof(TService));
            if (descriptor == null) return services;

            var newDescriptor = new ServiceDescriptor(typeof(TService), typeof(TImplementation), descriptor.Lifetime);
            services.Remove(descriptor);
            services.Add(newDescriptor);

            return services;
        }

        /// <summary>
        /// Replaces <typeparamref name="TService"/> implementation to the concrete instance of <typeparamref name="TService"/> if the service collection contains <typeparamref name="TService"/> descriptor.
        /// </summary>
        /// <typeparam name="TService">Abstraction type.</typeparam>
        /// <param name="services">Service Collection.</param>
        /// <param name="instance">Implementation instanbce.</param>
        /// <returns><see cref="IServiceCollection"/> for chaining.</returns>
        public static IServiceCollection ReplaceService<TService>(this IServiceCollection services, TService instance)
            where TService : class
        {
            var descriptor = services.SingleOrDefault(x => x.ServiceType == typeof(TService));
            if (descriptor == null) return services;

            var newDescriptor = new ServiceDescriptor(typeof(TService), instance);
            services.Remove(descriptor);
            services.Add(newDescriptor);

            return services;
        }

        /// <summary>
        /// Replaces <typeparamref name="TService"/> implementation to the concrete instance of <typeparamref name="TService"/> created by the specified factory if the service collection contains <typeparamref name="TService"/> descriptor.
        /// </summary>
        /// <typeparam name="TService">Abstraction type</typeparam>
        /// <param name="services">Service Collection.</param>
        /// <param name="factory">Implementation instance factory.</param>
        /// <returns><see cref="IServiceCollection"/> for chaining.</returns>
        public static IServiceCollection ReplaceService<TService>(this IServiceCollection services, Func<IServiceProvider, TService> factory)
            where TService : class
        {
            var descriptor = services.SingleOrDefault(x => x.ServiceType == typeof(TService));
            if (descriptor == null) return services;

            var newDescriptor = new ServiceDescriptor(typeof(TService), factory, descriptor.Lifetime);
            services.Remove(descriptor);
            services.Add(newDescriptor);

            return services;
        }
    }
}
