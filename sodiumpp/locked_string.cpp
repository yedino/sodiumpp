#include <cassert>
#include <sodiumpp/sodiumpp.h>
#include <sodiumpp/locked_string.h>

using namespace sodiumpp;

locked_string::locked_string(std::string &&str) noexcept {
	if (str.empty()) throw std::invalid_argument("input string is empty");
	m_str = std::move(str);
	assert( m_str.size() != 0 );
}

locked_string::locked_string()
	: locked_string(1)
{
}

locked_string::locked_string(const std::string &str) {
	if (str.empty()) throw std::invalid_argument("input string is empty");
	assert( str.size() != 0 );
	// TODO factor out the common part of all this constructors etc
    m_str.resize(str.size());
    const char * const data_ptr = &m_str[0];
    assert(m_str.size() == str.size());
    sodiumpp::mlock(m_str);
    str.copy(&m_str[0], str.size());
    assert(data_ptr == &m_str[0]);
}

locked_string::locked_string(size_t size) {
	if (size == 0) throw std::invalid_argument("size == 0");
	assert( size != 0 );
	m_str.resize(size);
	sodiumpp::mlock(m_str);
    assert(m_str.size() == size);
}

locked_string::locked_string(const locked_string & str) {
	auto size = str.size();
	assert( size != 0 ); // size always > 0 because cannot create empty locked_string
    m_str.resize(size);
    const char * const data_ptr = &m_str[0];
    assert(m_str.size() == str.size());
		sodiumpp::mlock(m_str);
		// m_str = str.get_string();
		for (size_t i=0; i<size; ++i) m_str[i] = str[i];
    assert(data_ptr == &m_str[0]);
}

locked_string & locked_string::operator=(const locked_string & str) {
	if (this == &str) return *this;
	sodiumpp::memzero(m_str);
	sodiumpp::munlock(m_str);
	m_str.resize(str.size());
	assert( m_str.size() != 0 );
	const char * const data_ptr = &m_str[0];
	assert(m_str.size() == str.size());
	sodiumpp::mlock(m_str);
	m_str = str.get_string();
	assert(data_ptr == &m_str[0]);
	return *this;
}

locked_string locked_string::move_from_locked_string(std::string &&str) {
    locked_string ret(std::move(str));
    return ret;
}

locked_string locked_string::move_from_not_locked_string(std::string &&str) {
    sodiumpp::mlock(str);
    locked_string ret(std::move(str));
    return ret;
}

locked_string::~locked_string() {
    sodiumpp::memzero(m_str);
    sodiumpp::munlock(m_str);
}

const std::string &locked_string::get_string() const {
    return m_str;
}

bool locked_string::operator==(const locked_string &rhs) {
    if (m_str.size() != rhs.m_str.size()) return false;
    if (sodium_memcmp(m_str.data(), rhs.m_str.data(), m_str.size()) == 0) return true;
    else return false;
}

bool locked_string::operator!=(const locked_string &rhs) {
    return !(*this == rhs);
}

size_t locked_string::size() const noexcept {
    return m_str.size();
}

bool locked_string::empty() const noexcept {
    return m_str.empty();
}

char &locked_string::operator[](size_t pos) {
    return m_str[pos];
}

const char &locked_string::operator[](size_t pos) const {
    return m_str[pos];
}

char &locked_string::at(size_t pos) {
    return m_str.at(pos);
}

const char &locked_string::at(size_t pos) const {
    return m_str.at(pos);
}

char &locked_string::back() {
    return m_str.back();
}

const char &locked_string::back() const {
    return m_str.back();
}

char &locked_string::front() {
    return m_str.front();
}

const char &locked_string::front() const {
    return m_str.front();
}

const char *locked_string::c_str() const noexcept {
    return m_str.c_str();
}

const char *locked_string::data() const noexcept {
    return m_str.data();
}

char * locked_string::buffer_writable() noexcept {
	assert( !m_str.empty() ); // UB to access s[0] if empty
	return &m_str[0] ;
}

