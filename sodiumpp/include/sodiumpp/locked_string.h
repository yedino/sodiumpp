#ifndef LOCKED_STRING_HPP
#define LOCKED_STRING_HPP

#include <string>

namespace sodiumpp {

/**
 * @nosubgrouping
 * @brief The locked_string class
 *
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
            //explicit locked_string(std::string && str) noexcept; ///< only move, not call mlock()
    public:
            locked_string() = default;
            locked_string(const locked_string &);
            locked_string(locked_string &&other);
            locked_string & operator=(const locked_string &);
            locked_string & operator=(locked_string &&other);

			/**
			 * @brief unsafe_create Creating locked string from obviously unsafe source.
			 * 						This is only for tests of course (as the memory is not-locked
			 * 						already before calling us
			 * @return locked_string UNSAFE!
			 * @{
			 */
//			static locked_string unsafe_create(const std::string &str);
//			static locked_string unsafe_create(const char *c_str);
			///@}

            // TODO: prove with standard c++11, that default move constructor of std::string
            // will preserve the address of memory of it's data - address of & .at(0)
            // or else write own secure versions of move constructors

            /**
             * @brief create locked string form non locked std::string, copy internal array.
             * @note Of course the current value of string str already was probably leaked,
             * because it was probably existing as a std::string before call to us,
             * therefore rather use constructor from locked_string
             * @param str
             */
            explicit locked_string(const std::string &str);

            /**
             * @brief create empty locked string
             * @param size size of internal string
             */
			locked_string(size_t size);
			/**
			 * @brief create empty locked string and fill it with char ch
			 * @param size size of internal string
			 * @param ch char to fill with
			 */
			locked_string(size_t size, char ch);

            /**
             * @brief move_from_locked_string
			 * @param str - The data, it will be "destroyed" (moved from, so caller should not use it later).
			 * 				It MUST BE already mlocked() by caler.
             * @return locked_string object
             */
//            static locked_string move_from_locked_string(std::string &&str);

            /**
             * @brief move_from_not_locked_string
             * @param str - the data, it will be "destroyed" (moved from, so caller should not use it later).
             * @return locked_string object
             */
//            static locked_string move_from_not_locked_string(std::string &&str);
            ~locked_string();

            /**
             * @return const reference to internal locked std::string, this does not yet make a copy of the data
             * but of course do NOT save result of it into a non-reference value std::string.
             */
            const std::string & get_string() const;

            /**
             * Comparison operators
             * sodium_memcmp() function is used inside
             */
            bool operator==(const locked_string &rhs) const;
            bool operator!=(const locked_string &rhs) const;

            /**
             * @name Secure getters
             * Secure getters, that do not make any copy of the locked memory content.
			 * std::string const funtions and non-const listed in 21.4.1.5
			 * @{
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
            std::string::iterator begin() noexcept;
            std::string::const_iterator begin() const noexcept;
            std::string::iterator end() noexcept;
            std::string::const_iterator end() const noexcept;
            /// @}

            /**
			 * @name Entire string
             * @note Do not compare this memory direct (i.e. using memcmp())
             * Use safe operators "==" and "!="
             * @{
             */
            const char *c_str() const noexcept;
            const char *data() const noexcept;

			/**
			* Returns pointer to writable, and safe (memlocked) memory of current string,
			* that can be both read and written in range:
			* inclusive p ..to.. p + size() exclusive, for p = data_writable()
			* in addition the character at index [ p+size() ] will contain NULL-character
			* and it is not allowed to write to this position (UB).
			* Of course you can not change length of this string just by writting data here,
			* e.g. any other NULL-character inside this string is just treated as any other character.
			*/
            char *buffer_writable() noexcept;
            /// @}
			size_t copy (char* s, size_t len, size_t pos = 0) const;
};

} // namespace

#endif // LOCKED_STRING_HPP
