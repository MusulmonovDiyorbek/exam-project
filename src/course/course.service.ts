import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateCourseDto } from './dto/create-course.dto';
import { UpdateCourseDto } from './dto/update-course.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Course } from './entities/course.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/entities/user.entity';

@Injectable()
export class CourseService {
  constructor(
    @InjectRepository(Course)
    private readonly courseRepository: Repository<Course>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ) { }

  async create(dto: CreateCourseDto): Promise<Course> {
    const teacher = await this.userRepository.findOneBy({ id: dto.teacherId });
    if (!teacher) {
      throw new Error('Bunday o\'qituvchi mavjud emas');
    }
    const course = this.courseRepository.create({ ...dto, teacher });
    return this.courseRepository.save(course);
  }
  findAll() {
    return this.courseRepository.find({ relations: ['teacher'] })
  }
  async findOne(id: number): Promise<Course> {
    const course = await this.courseRepository.findOne({
      where: { id },
      relations: ['teacher', 'model',]
    });
    if (!course) {
      throw new Error('Bunday kurs mavjud emas');
    }
    return course;
  }
  async update(id: number, dto: UpdateCourseDto) {
    const course = await this.findOne(id);

    if (dto.teacherId !== undefined) {
      const teacher = await this.userRepository.findOneBy({ id: dto.teacherId });
      if (!teacher) {
        throw new NotFoundException('Bunday teacher mavjud emas');
      }
    }
    Object.assign(course, dto);
    return this.courseRepository.save(course);
  }
  async remove(id: number) {
    const course = await this.findOne(id);
    if (!course) {
      throw new Error('Bunday kurs mavjud emas');
    }
    return this.courseRepository.remove(course);
  }
}
