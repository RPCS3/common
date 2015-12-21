#pragma once
#include <deque>
#include <memory>

struct sleep_entry_t : protected std::enable_shared_from_this<sleep_entry_t>
{
	virtual void sleep() = 0;
	virtual void awake() = 0;

	friend class sleep_queue_entry_t;
};

using sleep_queue_t = std::deque<std::shared_ptr<sleep_entry_t>>;

static struct defer_sleep_t {} const defer_sleep{};

// automatic object handling a thread entry in the sleep queue
class sleep_queue_entry_t final
{
	sleep_entry_t& m_thread;
	sleep_queue_t& m_queue;

	void add_entry();
	void remove_entry();
	bool find() const;

public:
	// add specified thread to the sleep queue
	sleep_queue_entry_t(sleep_entry_t& entry, sleep_queue_t& queue);

	// don't add specified thread to the sleep queue
	sleep_queue_entry_t(sleep_entry_t& entry, sleep_queue_t& queue, const defer_sleep_t&);

	// removes specified thread from the sleep queue if added
	~sleep_queue_entry_t();

	// add thread to the sleep queue
	void enter()
	{
		add_entry();
	}

	// remove thread from the sleep queue
	void leave()
	{
		remove_entry();
	}

	// check whether the thread exists in the sleep queue
	explicit operator bool() const
	{
		return find();
	}
};
