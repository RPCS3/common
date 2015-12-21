#include "SleepQueue.h"

void sleep_queue_entry_t::add_entry()
{
	m_queue.emplace_back(std::static_pointer_cast<sleep_entry_t>(m_thread.shared_from_this()));
}

void sleep_queue_entry_t::remove_entry()
{
	for (auto it = m_queue.begin(); it != m_queue.end(); it++)
	{
		if (it->get() == &m_thread)
		{
			m_queue.erase(it);
			return;
		}
	}
}

bool sleep_queue_entry_t::find() const
{
	for (auto it = m_queue.begin(); it != m_queue.end(); it++)
	{
		if (it->get() == &m_thread)
		{
			return true;
		}
	}

	return false;
}

sleep_queue_entry_t::sleep_queue_entry_t(sleep_entry_t& cpu, sleep_queue_t& queue)
	: m_thread(cpu)
	, m_queue(queue)
{
	add_entry();
	cpu.sleep();
}

sleep_queue_entry_t::sleep_queue_entry_t(sleep_entry_t& cpu, sleep_queue_t& queue, const defer_sleep_t&)
	: m_thread(cpu)
	, m_queue(queue)
{
	cpu.sleep();
}

sleep_queue_entry_t::~sleep_queue_entry_t()
{
	remove_entry();
	m_thread.awake();
}
