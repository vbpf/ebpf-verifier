// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "debug.hpp"
#include <optional>

namespace crab {
    /**
     * @brief The default factory for lazy_allocator that creates objects using the default constructor.
     *
     * @tparam T The type of the object to create.
     */
    template <typename T>
    struct lazy_allocator_default_factory {
        T operator()() { return T(); }
    };

    /**
     * @brief A factory that fails the allocation of objects (to enforce setting the value before using it).
     *
     * @tparam T The type of the object to create.
     */
    template <typename T>
    struct lazy_allocator_no_default_factory {
        T operator()() { CRAB_ERROR("lazy_allocator_no_default"); }
    };

    /**
     * @brief Lazy allocator for objects of type T. The allocator does not allocate the object until it is first accessed.
     *
     * @tparam T The type of the object to allocate.
     * @tparam factory The factory to use to create the object. The factory must be callable with no arguments and return an object of type T.
     *                The default factory creates the object using the default constructor.
     *                The no_default_factory fails the allocation of the object.
     *                The caller can provide a custom factory to create the object in a specific way.
     */
    template <typename T, template <typename TInner> typename factory = lazy_allocator_default_factory>
    class lazy_allocator {
        std::optional<T> _value;

      public:
        /**
         * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
         *
         * @return The allocated object.
         */
        T& get() {
            if (!_value.has_value()) {
                _value = factory<T>()();
            }
            return _value.value();
        }

        /**
         * @brief Delete the currently allocated object.
         */
        void clear() {
            _value.reset();
        }

        /**
         * @brief Allocate the object using the value.
         *
         * @param[in] value The value to copy.
         */
        void set(T value) {
            _value = value;
        }

        // Ideally we would overload the . operator, but that is not possible
        // so we use -> instead and modify the callers from . to ->

        /**
         * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
         *
         * @return The allocated object.
         */
        T* operator->() {
            return &get();
        }

        /**
         * @brief Get the currently allocated object or allocate it if it has not been allocated yet.
         *
         * @return The allocated object.
         */
        T& operator*() {
            return get();
        }

        /**
         * @brief Assign the value to the currently allocated object.
         *
         * @param[in] value The value to assign.
         * @return The allocated object.
         */
        T& operator=(const T& value) {
            _value.emplace(value);
            return get();
        }
    };
}
