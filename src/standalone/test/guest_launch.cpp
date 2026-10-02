// Native regression for the coordinator used by hold_injected_clients.
// c++ -std=c++20 -pthread src/standalone/test/guest_launch.cpp -o /tmp/guest_launch_test
#include "../../component/splitscreen_guest_launch.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <stdexcept>
#include <thread>

namespace
{
	void check(const bool ok, const char* what)
	{
		if (!ok)
		{
			std::fprintf(stderr, "FAIL: %s\n", what);
			std::abort();
		}
	}

	void overlap_and_retry(const char* first_driver)
	{
		splitscreen::guest_launch_coordinator coordinator;
		std::atomic<unsigned> reference{40};
		unsigned guest = 0;
		unsigned snapshots = 0;
		std::promise<void> entered;
		std::promise<void> resume;
		auto entered_future = entered.get_future();
		auto resume_future = resume.get_future();
		bool first_ran = false;

		std::thread first([&]
		{
			first_ran = coordinator.try_run([&]
			{
				const auto snapshot = reference.load();
				++snapshots;
				entered.set_value();
				resume_future.wait();
				guest = snapshot;
			});
		});

		entered_future.wait(); // The first callback owns the guard and its snapshot.
		reference = 100;
		const auto second_ran = coordinator.try_run([&]
		{
			++snapshots;
			guest = reference.load();
		});
		check(!second_ran, "overlapping callback returns without waiting");
		check(snapshots == 1, "rejected callback does not read a snapshot or write");

		resume.set_value();
		first.join();
		check(first_ran && guest == 40, "first callback finishes normally");
		check(coordinator.try_run([&]
		{
			++snapshots;
			guest = reference.load();
		}), "other driver can retry after the first exits");
		check(guest == 100 && snapshots == 2, "retry reads the newer state after acquisition");
		std::printf("PASS: overlap skip and fresh retry, first driver %s\n", first_driver);
	}
}

int main()
{
	// Either pipeline can arrive first; the coordinator assigns no ownership.
	overlap_and_retry("async");
	overlap_and_retry("renderer");

	splitscreen::guest_launch_coordinator coordinator;
	check(coordinator.try_run([&]
	{
		check(!coordinator.try_run([] {}), "reentrant callback skips without deadlock");
		return;
	}), "outer callback runs");
	check(coordinator.try_run([] {}), "normal/early callback return releases the guard");

	try
	{
		coordinator.try_run([] { throw std::runtime_error("test exit"); });
		check(false, "exception propagates");
	}
	catch (const std::runtime_error&)
	{
	}
	check(coordinator.try_run([] {}), "exception exit releases the guard");
	std::puts("PASS: reentrancy and release on every C++ exit");
}
