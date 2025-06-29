import { forwardRef, Inject, Injectable } from '@nestjs/common';
import { CreateModelDto } from './dto/create-model.dto';
import { UpdateModelDto } from './dto/update-model.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Model } from './entities/model.entity';
import { Repository } from 'typeorm';
import { CourseService } from 'src/course/course.service';

@Injectable()
export class ModelService {
  constructor(
    @InjectRepository(Model)
    private modelRepo: Repository<Model>,
    
    @Inject(forwardRef(() => CourseService))
    private courseService: CourseService,
  ) { }

  async create(dto: CreateModelDto): Promise<Model> {
    const course = await this.courseService.findOne(dto.courseId);
    if (!course) {
      throw new Error('Bunday kurs mavjud emas');
    }
    const model = this.modelRepo.create({ ...dto, course });
    return this.modelRepo.save(model);
  }
  findAll() {
    return this.modelRepo.find({ relations: ['course'] })
  }
  async findByCourseId(courseId: number) {
    return this.modelRepo.find({ where: { course: { id: courseId } } });
  }

  async findOne(id: number) {
    const model = await this.modelRepo.findOne({
      where: { id },
      relations: ['course', 'lessons'],
    });
    if (!model) {
      throw new Error('Bunday model mavjud emas');
    }
    return model;
  }
  async update(id: number, dto: UpdateModelDto) {
    const model = await this.modelRepo.findOneBy({ id });
    if(!model){
      throw new Error('Bunday model mavjud emas');
    }
    Object.assign(model,dto);
    return this.modelRepo.save(model);
  }
  async remove(id:number){
    const model = await this.modelRepo.findOneBy({id});
    if(!model){
      throw new Error('Bunday model mavjud emas');
    }
    return this.modelRepo.remove(model);
  }
}
