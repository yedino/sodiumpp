#ifndef LOCKED_STRING_HPP
#define LOCKED_STRING_HPP

#include <string>

namespace sodiumpp {

/**
 * @brief The locked_string class
 * Conatin std::string object
 * Internal string data is always locked by sodiumpp::mlock() function
 */

class locked_string final
{
    private:
            std::string m_str;
            /**
             * only move, not call mlock()
             * for move construction for std::string use static methods:
             * move_from_locked_string() and move_from_not_locked_string
             */
            explicit locked_string(std::string && str) noexcept; ///< only move, not call mlock()
    public:
            locked_string() = default;
            locked_string(const locked_string &) = default;
            locked_string(locked_string &&) = default;
            locked_string &operator=(const locked_string &) = default;
            locked_string &operator=(locked_string &&) = default;

            /**
             * @brief create locked string form non locked std::string, copy internal array
             * @param str
             */
            explicit locked_string(const std::string &str);

            /**
             * @brief create empty locked string
             * @param size size of internal string
             */
            locked_string(size_t size);

            /**
             * @brief move_from_locked_string
             * @param str - the data, it will be "destroyed" (moved from, so caller should not use it later). It MUST BE already mlocked() by caler.
             * @return locked_string object
             */
            static locked_string move_from_locked_string(std::string &&str);

            /**
             * @brief move_from_not_locked_string
             * @param str - the data, it will be "destroyed" (moved from, so caller should not use it later).
             * @return locked_string object
             */
            static locked_string move_from_not_locked_string(std::string &&str);
            ~locked_string();

            /**
             * @return const reference to internal locked std::string
             */
            const std::string & get_string() const;

            /**
             * Comparison operators
             * sodium_memcmp() function is used inside
             */
            bool operator==(const locked_string &rhs);
            bool operator!=(const locked_string &rhs);

            /**
             * std::string const funtions and non-const listed in 21.4.1.5
             */
            size_t size() const noexcept;
            bool empty() const noexcept;
            char &operator[] (size_t pos);
            const char &operator[] (size_t pos) const;
            char &at (size_t pos);
            const char& at (size_t pos) const;
            char &back();
            const char &back() const;
            char &front();
            const char &front() const;

            /**
             * Do not compare this memory direct (i.e. using memcmp())
             * Use safe operators "==" and "!="
             */
            const char *c_str() const noexcept;
            const char *data() const noexcept;
};

} // namespace

#endif // LOCKED_STRING_HPP
